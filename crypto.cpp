#include "crypto.h"
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

namespace Crypto {

QByteArray deriveKey(const QString &psk)
{
    return QCryptographicHash::hash(psk.toUtf8(), QCryptographicHash::Sha256);
}

QByteArray encrypt(const QByteArray &plaintext, const QByteArray &key)
{
    if (key.size() != 32)
        throw std::runtime_error("Key must be 32 bytes");

    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1)
        throw std::runtime_error("Failed to generate IV");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char*>(key.constData()),
                           iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    QByteArray ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx,
                          reinterpret_cast<unsigned char*>(ciphertext.data()),
                          &len,
                          reinterpret_cast<const unsigned char*>(plaintext.constData()),
                          plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char*>(ciphertext.data()) + len,
                            &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);

    // Prepend IV
    QByteArray result;
    result.append(reinterpret_cast<const char*>(iv), 16);
    result.append(ciphertext);
    return result;
}

QByteArray decrypt(const QByteArray &data, const QByteArray &key)
{
    if (key.size() != 32 || data.size() < 17)
        throw std::runtime_error("Invalid data or key");

    const unsigned char *iv = reinterpret_cast<const unsigned char*>(data.constData());
    const unsigned char *ciphertext = iv + 16;
    int ciphertext_len = data.size() - 16;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char*>(key.constData()),
                           iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    QByteArray plaintext(ciphertext_len + EVP_MAX_BLOCK_LENGTH, 0);
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx,
                          reinterpret_cast<unsigned char*>(plaintext.data()),
                          &len,
                          ciphertext,
                          ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char*>(plaintext.data()) + len,
                            &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed (wrong key?)");
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    return plaintext;
}

} // namespace Crypto
