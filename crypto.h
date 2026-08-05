#pragma once
#include <QByteArray>
#include <QString>

namespace Crypto {

QByteArray deriveKey(const QString &psk);

// AES-256-GCM. Returns IV (12 bytes) + ciphertext + authentication tag (16 bytes)
QByteArray encrypt(const QByteArray &plaintext, const QByteArray &key);

// Expects IV (12 bytes) + ciphertext + authentication tag (16 bytes).
// Throws if the tag doesn't verify (tampered data or wrong key).
QByteArray decrypt(const QByteArray &data, const QByteArray &key);

} // namespace Crypto
