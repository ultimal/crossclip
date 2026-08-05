#pragma once
#include <QByteArray>
#include <QString>

namespace Crypto {

QByteArray deriveKey(const QString &psk);

// Returns IV (16 bytes) + ciphertext
QByteArray encrypt(const QByteArray &plaintext, const QByteArray &key);

// Expects IV (16 bytes) + ciphertext
QByteArray decrypt(const QByteArray &data, const QByteArray &key);

} // namespace Crypto
