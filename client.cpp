#include <QGuiApplication>
#include <QClipboard>
#include <QTcpSocket>
#include <QMimeData>
#include <QImage>
#include <QBuffer>
#include <QFile>
#include <QFileInfo>
#include <QUrl>
#include <QStandardPaths>
#include <QDebug>
#include <QDataStream>
#include <QTimer>

#include "crypto.h"
#include "protocol.h"

class ClipboardClient : public QObject
{
    Q_OBJECT
public:
    explicit ClipboardClient(const QString &host, quint16 port, const QString &psk, QObject *parent = nullptr)
        : QObject(parent)
        , m_host(host)
        , m_port(port)
        , m_key(Crypto::deriveKey(psk))
        , m_socket(new QTcpSocket(this))
    {
        m_clipboard = QGuiApplication::clipboard();

        connect(m_socket, &QTcpSocket::connected, this, &ClipboardClient::onConnected);
        connect(m_socket, &QTcpSocket::readyRead, this, &ClipboardClient::onReadyRead);
        connect(m_socket, &QTcpSocket::disconnected, this, &ClipboardClient::onDisconnected);
        connect(m_socket, &QTcpSocket::errorOccurred, this, &ClipboardClient::onSocketError);

        // Local clipboard → send to server
        connect(m_clipboard, &QClipboard::dataChanged, this, &ClipboardClient::onLocalClipboardChanged);

        connectToServer();
    }

private slots:
    void connectToServer()
    {
        qInfo() << "Connecting to" << m_host << ":" << m_port << "...";
        m_socket->connectToHost(m_host, m_port);
    }

    void onConnected()
    {
        // Authenticate
        m_socket->write(m_key);
        qInfo() << "Connected – authenticating...";
    }

    void onDisconnected()
    {
        qWarning() << "Disconnected from server – reconnecting in"
                    << kReconnectDelayMs / 1000 << "s";
        scheduleReconnect();
    }

    void onSocketError(QAbstractSocket::SocketError)
    {
        qWarning() << "Socket error:" << m_socket->errorString()
                    << "– reconnecting in" << kReconnectDelayMs / 1000 << "s";
        scheduleReconnect();
    }

    void scheduleReconnect()
    {
        m_authenticated = false;
        m_buffer.clear();

        if (m_reconnectPending)
            return;
        m_reconnectPending = true;

        QTimer::singleShot(kReconnectDelayMs, this, [this]() {
            m_reconnectPending = false;
            m_socket->abort();
            connectToServer();
        });
    }

    void onReadyRead()
    {
        m_buffer.append(m_socket->readAll());

        // First reply from server is "OK"
        if (!m_authenticated) {
            if (m_buffer.startsWith("OK")) {
                m_authenticated = true;
                m_buffer.remove(0, 2);
                qInfo() << "Authenticated successfully. Clipboard sync active.";
            }
            return;
        }

        // Process incoming length-prefixed encrypted packets
        while (m_buffer.size() >= 4) {
            QDataStream ds(m_buffer);
            ds.setVersion(QDataStream::Qt_6_5);

            QByteArray encrypted;
            ds >> encrypted;

            if (ds.status() != QDataStream::Ok)
                break;

            int consumed = static_cast<int>(ds.device()->pos());
            m_buffer.remove(0, consumed);

            try {
                QByteArray plain = Crypto::decrypt(encrypted, m_key);
                ClipboardPayload payload;
                if (deserializePayload(plain, payload)) {
                    applyPayload(payload);
                }
            } catch (const std::exception &e) {
                qCritical() << "Decryption failed:" << e.what();
            }
        }
    }

    void onLocalClipboardChanged()
    {
        if (m_ignoreNextChange) {
            m_ignoreNextChange = false;
            return;
        }

        if (!m_authenticated || m_socket->state() != QAbstractSocket::ConnectedState)
            return;

        const QMimeData *mime = m_clipboard->mimeData();
        if (!mime)
            return;

        ClipboardPayload payload;

        if (mime->hasImage()) {
            QImage img = qvariant_cast<QImage>(mime->imageData());
            if (!img.isNull()) {
                QByteArray png;
                QBuffer buffer(&png);
                buffer.open(QIODevice::WriteOnly);
                img.save(&buffer, "PNG");
                payload.type = ClipType::Image;
                payload.imagePng = png;
                qInfo() << "Sending image (" << png.size() << "bytes)";
            }
        }
        else if (mime->hasUrls()) {
            const QList<QUrl> urls = mime->urls();
            if (!urls.isEmpty() && urls.first().isLocalFile()) {
                QString path = urls.first().toLocalFile();
                QFileInfo fi(path);
                if (fi.isFile()) {
                    QFile f(path);
                    if (f.open(QIODevice::ReadOnly)) {
                        payload.type = ClipType::File;
                        payload.fileName = fi.fileName();
                        payload.fileData = f.readAll();
                        qInfo() << "Sending file:" << payload.fileName
                                << "(" << payload.fileData.size() << "bytes)";
                    }
                } else if (fi.isDir()) {
                    qWarning() << "Directories are not supported yet:" << path;
                    return;
                }
            }
        }
        else if (mime->hasText()) {
            payload.type = ClipType::Text;
            payload.text = mime->text();
            qInfo() << "Sending text:" << payload.text.left(60);
        }
        else {
            return;
        }

        // Encrypt and send
        try {
            QByteArray plain = serializePayload(payload);
            QByteArray encrypted = Crypto::encrypt(plain, m_key);

            QByteArray packet;
            QDataStream out(&packet, QIODevice::WriteOnly);
            out.setVersion(QDataStream::Qt_6_5);
            out << encrypted;

            m_socket->write(packet);
        } catch (const std::exception &e) {
            qCritical() << "Encryption error:" << e.what();
        }
    }

    void applyPayload(const ClipboardPayload &p)
    {
        QMimeData *mime = new QMimeData;

        switch (p.type) {
        case ClipType::Text:
            mime->setText(p.text);
            qInfo() << "Received text:" << p.text.left(80);
            break;

        case ClipType::Image: {
            QImage img;
            img.loadFromData(p.imagePng, "PNG");
            if (!img.isNull()) {
                mime->setImageData(img);
                qInfo() << "Received image" << img.size();
            }
            break;
        }

        case ClipType::File: {
            QString dir = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
            QString path = dir + "/" + p.fileName;
            QFile f(path);
            if (f.open(QIODevice::WriteOnly)) {
                f.write(p.fileData);
                f.close();
                mime->setUrls({QUrl::fromLocalFile(path)});
                qInfo() << "Received file → saved to" << path;
            }
            break;
        }
        }

        // Prevent the setMimeData from triggering a send-back loop
        m_ignoreNextChange = true;
        m_clipboard->setMimeData(mime);
    }

private:
    static constexpr int kReconnectDelayMs = 3000;

    QString m_host;
    quint16 m_port;
    QByteArray m_key;
    QTcpSocket *m_socket;
    QClipboard *m_clipboard = nullptr;
    QByteArray m_buffer;
    bool m_authenticated = false;
    bool m_ignoreNextChange = false;
    bool m_reconnectPending = false;
};

#include "client.moc"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    if (argc < 4) {
        qCritical() << "Usage:" << argv[0] << "<server-ip> <port> <psk>";
        return 1;
    }

    QString host = QString::fromLocal8Bit(argv[1]);
    quint16 port = QString::fromLocal8Bit(argv[2]).toUShort();
    QString psk  = QString::fromLocal8Bit(argv[3]);

    ClipboardClient client(host, port, psk);
    return app.exec();
}
