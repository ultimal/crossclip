#include <QCoreApplication>
#include <QTcpServer>
#include <QTcpSocket>
#include <QDebug>
#include <QDataStream>

#include "crypto.h"
#include "protocol.h"

class ClipboardServer : public QObject
{
    Q_OBJECT
public:
    explicit ClipboardServer(const QString &psk, quint16 port, QObject *parent = nullptr)
        : QObject(parent)
        , m_key(Crypto::deriveKey(psk))
        , m_server(new QTcpServer(this))
    {
        connect(m_server, &QTcpServer::newConnection, this, &ClipboardServer::onNewConnection);

        if (!m_server->listen(QHostAddress::Any, port)) {
            qCritical() << "Failed to listen on port" << port << ":" << m_server->errorString();
            return;
        }
        qInfo() << "Relay server listening on port" << port;
        qInfo() << "Waiting for clients...";
    }

private slots:
    void onNewConnection()
    {
        while (QTcpSocket *socket = m_server->nextPendingConnection()) {
            qInfo() << "New connection from" << socket->peerAddress().toString();

            // Each client has its own receive buffer
            m_buffers[socket] = QByteArray();

            connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
                handleClientData(socket);
            });

            connect(socket, &QTcpSocket::disconnected, this, [this, socket]() {
                m_clients.removeAll(socket);
                m_buffers.remove(socket);
                m_authenticated.remove(socket);
                socket->deleteLater();
                qInfo() << "Client disconnected. Remaining clients:" << m_clients.size();
            });
        }
    }

    void handleClientData(QTcpSocket *socket)
    {
        m_buffers[socket].append(socket->readAll());
        QByteArray &buffer = m_buffers[socket];

        // ----- Authentication phase -----
        if (!m_authenticated.value(socket, false)) {
            // Client must send exactly the 32-byte key (SHA-256 of PSK)
            if (buffer.size() >= 32) {
                QByteArray receivedKey = buffer.left(32);
                buffer.remove(0, 32);

                if (receivedKey == m_key) {
                    m_authenticated[socket] = true;
                    m_clients.append(socket);
                    socket->write("OK");
                    qInfo() << "Client authenticated:" << socket->peerAddress().toString()
                            << "  Total clients:" << m_clients.size();
                } else {
                    qWarning() << "Authentication failed from" << socket->peerAddress().toString();
                    socket->disconnectFromHost();
                }
            }
            return;
        }

        // ----- Normal message phase (length-prefixed encrypted payloads) -----
        while (buffer.size() >= 4) {
            QDataStream ds(buffer);
            ds.setVersion(QDataStream::Qt_6_5);

            QByteArray encrypted;
            ds >> encrypted;

            if (ds.status() != QDataStream::Ok)
                break;   // incomplete packet

            int consumed = static_cast<int>(ds.device()->pos());
            buffer.remove(0, consumed);

            // Optional: decrypt just to log what arrived
            try {
                QByteArray plain = Crypto::decrypt(encrypted, m_key);
                ClipboardPayload payload;
                if (deserializePayload(plain, payload)) {
                    switch (payload.type) {
                    case ClipType::Text:
                        qInfo() << "Relaying text from" << socket->peerAddress().toString()
                                << "→" << payload.text.left(60);
                        break;
                    case ClipType::Image:
                        qInfo() << "Relaying image from" << socket->peerAddress().toString()
                                << "(" << payload.imagePng.size() << "bytes)";
                        break;
                    case ClipType::File:
                        qInfo() << "Relaying file from" << socket->peerAddress().toString()
                                << "→" << payload.fileName;
                        break;
                    }
                }
            } catch (...) {
                qWarning() << "Received invalid encrypted packet – ignoring";
                continue;
            }

            // Re-broadcast the *same encrypted packet* to every other client
            QByteArray packet;
            QDataStream out(&packet, QIODevice::WriteOnly);
            out.setVersion(QDataStream::Qt_6_5);
            out << encrypted;

            for (QTcpSocket *client : std::as_const(m_clients)) {
                if (client != socket && client->state() == QAbstractSocket::ConnectedState) {
                    client->write(packet);
                }
            }
        }
    }

private:
    QByteArray m_key;
    QTcpServer *m_server;
    QList<QTcpSocket*> m_clients;
    QHash<QTcpSocket*, QByteArray> m_buffers;
    QHash<QTcpSocket*, bool> m_authenticated;
};

#include "server.moc"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    if (argc < 3) {
        qCritical() << "Usage:" << argv[0] << "<psk> <port>";
        return 1;
    }

    QString psk  = QString::fromLocal8Bit(argv[1]);
    quint16 port = QString::fromLocal8Bit(argv[2]).toUShort();

    ClipboardServer server(psk, port);
    return app.exec();
}
