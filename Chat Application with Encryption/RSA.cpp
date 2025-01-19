#include "RSA.h"


RSA::RSA() {
    publicKey = nullptr;
    privateKey = nullptr;
    OpenSSL_add_all_algorithms(); // Initialize OpenSSL
}

RSA::~RSA() {
    if (publicKey) RSA_free(publicKey);
    if (privateKey) RSA_free(privateKey);
}

// Function to generate RSA keys
void RSA::generateKeys() {
    privateKey = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    publicKey = RSAPublicKey_dup(privateKey); // Create public key from private key
}

// Encrypt data using RSA public key
std::string RSA::encrypt(const std::string &data) {
    std::vector<unsigned char> encrypted(RSA_size(publicKey));
    int encryptedLen = RSA_public_encrypt(data.size(), (unsigned char *)data.c_str(), encrypted.data(), publicKey, RSA_PKCS1_OAEP_PADDING);
    if (encryptedLen == -1) {
        std::cerr << "Encryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        exit(1);
    }
    return std::string((char *)encrypted.data(), encryptedLen);
}

// Decrypt data using RSA private key
std::string RSA::decrypt(const std::string &data) {
    std::vector<unsigned char> decrypted(RSA_size(privateKey));
    int decryptedLen = RSA_private_decrypt(data.size(), (unsigned char *)data.c_str(), decrypted.data(), privateKey, RSA_PKCS1_OAEP_PADDING);
    if (decryptedLen == -1) {
        std::cerr << "Decryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        exit(1);
    }
    return std::string((char *)decrypted.data(), decryptedLen);
}
