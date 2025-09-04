#include "cryptohelper.h"

#include <QString>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/oaep.h>
#include <cryptopp/pssr.h>
#include <cryptopp/base64.h>
#include <cryptopp/queue.h>
#include <cryptopp/secblock.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/gcm.h>

#include <fstream>
#include <sstream>
#include <stdexcept>

using namespace CryptoPP;

namespace CryptoHelper {

// Helper: convert PEM -> DER bytes (strip headers and base64 decode)
static bool pemToDer(const std::string &pem, std::string &der) {
    std::istringstream iss(pem);
    std::string line;
    std::string b64;
    bool in = false;
    while (std::getline(iss, line)) {
        if (line.rfind("-----BEGIN", 0) == 0) { in = true; continue; }
        if (line.rfind("-----END", 0) == 0) break;
        if (in) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            b64 += line;
        }
    }
    if (b64.empty()) return false;
    try {
        StringSource ss(b64, true, new Base64Decoder(new StringSink(der)));
    } catch (...) {
        return false;
    }
    return true;
}

bool loadPublicKeyPEM(const QString &path, RSA::PublicKey &pub) {
    std::ifstream ifs(path.toStdString(), std::ios::in);
    if (!ifs) return false;
    std::stringstream ssIn;
    ssIn << ifs.rdbuf();
    std::string pem = ssIn.str();
    std::string der;
    if (!pemToDer(pem, der)) return false;

    try {
        ByteQueue queue;
        queue.Put((const byte*)der.data(), der.size());
        queue.MessageEnd();
        pub.BERDecode(queue);
    } catch (...) {
        return false;
    }
    return true;
}

bool loadPrivateKeyPEM(const QString &path, RSA::PrivateKey &priv) {
    std::ifstream ifs(path.toStdString(), std::ios::in);
    if (!ifs) return false;
    std::stringstream ssIn;
    ssIn << ifs.rdbuf();
    std::string pem = ssIn.str();
    std::string der;
    if (!pemToDer(pem, der)) return false;

    try {
        ByteQueue queue;
        queue.Put((const byte*)der.data(), der.size());
        queue.MessageEnd();
        priv.BERDecode(queue);
    } catch (...) {
        return false;
    }
    return true;
}

std::string rsaEncrypt(const RSA::PublicKey &pub, const std::string &plain) {
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor e(pub);
    std::string cipher;
    StringSource ss(plain, true,
        new PK_EncryptorFilter(rng, e, new StringSink(cipher)));
    return cipher;
}

std::string rsaDecrypt(const RSA::PrivateKey &priv, const std::string &cipher) {
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Decryptor d(priv);
    std::string recovered;
    StringSource ss(cipher, true,
        new PK_DecryptorFilter(rng, d, new StringSink(recovered)));
    return recovered;
}

/*
 * AES-GCM Encryption:
 *   Generates random AES key and random 12-byte IV.
 *   Returns ciphertext+tag. IV is provided separately via outIV.
 */
std::string aesEncryptWithRandomKeyGCM(
    const std::string &plain,
    CryptoPP::SecByteBlock &outKey,
    std::string &outIV,
    size_t keySize
) {
    AutoSeededRandomPool prng;

    // Generate random AES key
    outKey = SecByteBlock(keySize);
    prng.GenerateBlock(outKey, outKey.size());

    // Generate random IV (12 bytes recommended for GCM)
    SecByteBlock iv(12);
    prng.GenerateBlock(iv, iv.size());
    outIV.assign(reinterpret_cast<const char*>(iv.data()), iv.size());

    // Encrypt
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(outKey, outKey.size(), iv, iv.size());

    std::string cipher;
    StringSource ss(
        plain, true,
        new AuthenticatedEncryptionFilter(enc,
            new StringSink(cipher)
        )
    );

    return cipher;
}

/*
 * AES-GCM Decryption:
 *   Takes ciphertext+tag and IV (must be 12 bytes).
 */
std::string aesDecryptWithKeyGCM(
    const std::string &cipherWithTag,
    const CryptoPP::SecByteBlock &key,
    const std::string &ivStr
) {
    SecByteBlock iv(reinterpret_cast<const byte*>(ivStr.data()), ivStr.size());

    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    std::string recovered;
    StringSource ss(
        cipherWithTag, true,
        new AuthenticatedDecryptionFilter(dec,
            new StringSink(recovered)
        )
    );

    return recovered;
}

} // namespace CryptoHelper
