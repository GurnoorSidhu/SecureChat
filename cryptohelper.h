#pragma once

#include <string>
#include <cryptopp/secblock.h>
#include <cryptopp/rsa.h>
#include <QString>

namespace CryptoHelper {

bool loadPublicKeyPEM(const QString &path, CryptoPP::RSA::PublicKey &pub);
bool loadPrivateKeyPEM(const QString &path, CryptoPP::RSA::PrivateKey &priv);

std::string rsaEncrypt(const CryptoPP::RSA::PublicKey &pub, const std::string &plain);
std::string rsaDecrypt(const CryptoPP::RSA::PrivateKey &priv, const std::string &cipher);

// AES-GCM helpers
std::string aesEncryptWithRandomKeyGCM(const std::string &plain,
                                       CryptoPP::SecByteBlock &outKey,
                                       std::string &outIV,
                                       size_t keySize = 32);

std::string aesDecryptWithKeyGCM(const std::string &cipherWithTag,
                                 const CryptoPP::SecByteBlock &key,
                                 const std::string &iv);

} // namespace CryptoHelper
