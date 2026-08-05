#include "crypto.h"
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>

namespace Crypto {

namespace {
constexpr int kIvLen = 12;
constexpr int kTagLen = 16;

struct CtxGuard {
    EVP_CIPHER_CTX *ctx;
    ~CtxGuard() { EVP_CIPHER_CTX_free(ctx); }
};
} // namespace

QByteArray deriveKey(const QString &psk)
{
    return QCryptographicHash::hash(psk.toUtf8(), QCryptographicHash::Sha256);
}

QByteArray encrypt(const QByteArray &plaintext, const QByteArray &key)
{
    if (key.size() != 32)
        throw std::runtime_error("Key must be 32 bytes");

    unsigned char iv[kIvLen];
    if (RAND_bytes(iv, sizeof(iv)) != 1)
        throw std::runtime_error("Failed to generate IV");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    CtxGuard guard{ctx};

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, nullptr) != 1)
        throw std::runtime_error("Failed to set GCM IV length");

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(key.constData()),
                           iv) != 1) {
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
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char*>(ciphertext.data()) + len,
                            &len) != 1) {
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    unsigned char tag[kTagLen];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen, tag) != 1)
        throw std::runtime_error("Failed to get GCM tag");

    QByteArray result;
    result.reserve(kIvLen + ciphertext.size() + kTagLen);
    result.append(reinterpret_cast<const char*>(iv), kIvLen);
    result.append(ciphertext);
    result.append(reinterpret_cast<const char*>(tag), kTagLen);
    return result;
}

QByteArray decrypt(const QByteArray &data, const QByteArray &key)
{
    if (key.size() != 32 || data.size() < kIvLen + kTagLen)
        throw std::runtime_error("Invalid data or key");

    const unsigned char *iv = reinterpret_cast<const unsigned char*>(data.constData());
    const unsigned char *ciphertext = iv + kIvLen;
    int ciphertext_len = data.size() - kIvLen - kTagLen;

    unsigned char tag[kTagLen];
    std::memcpy(tag, data.constData() + data.size() - kTagLen, kTagLen);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    CtxGuard guard{ctx};

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, nullptr) != 1)
        throw std::runtime_error("Failed to set GCM IV length");

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(key.constData()),
                           iv) != 1) {
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
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen, tag) != 1)
        throw std::runtime_error("Failed to set GCM tag");

    if (EVP_DecryptFinal_ex(ctx,
                            reinterpret_cast<unsigned char*>(plaintext.data()) + len,
                            &len) != 1) {
        throw std::runtime_error("Authentication failed (tampered data or wrong key)");
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    return plaintext;
}

} // namespace Crypto
