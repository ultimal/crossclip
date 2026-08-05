#pragma once
#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QString>

enum class ClipType : quint8 {
    Text  = 1,
    Image = 2,
    File  = 3
};

struct ClipboardPayload {
    ClipType type = ClipType::Text;
    QString  text;
    QByteArray imagePng;   // PNG data
    QString  fileName;
    QByteArray fileData;
};

inline QByteArray serializePayload(const ClipboardPayload &p)
{
    QByteArray ba;
    QDataStream out(&ba, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_5);

    out << static_cast<quint8>(p.type);

    switch (p.type) {
    case ClipType::Text:
        out << p.text;
        break;
    case ClipType::Image:
        out << p.imagePng;
        break;
    case ClipType::File:
        out << p.fileName << p.fileData;
        break;
    }
    return ba;
}

inline bool deserializePayload(const QByteArray &ba, ClipboardPayload &p)
{
    QDataStream in(ba);
    in.setVersion(QDataStream::Qt_6_5);

    quint8 t = 0;
    in >> t;
    p.type = static_cast<ClipType>(t);

    switch (p.type) {
    case ClipType::Text:
        in >> p.text;
        break;
    case ClipType::Image:
        in >> p.imagePng;
        break;
    case ClipType::File:
        in >> p.fileName >> p.fileData;
        break;
    default:
        return false;
    }
    return in.status() == QDataStream::Ok;
}
