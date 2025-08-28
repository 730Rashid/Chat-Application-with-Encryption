#include "MyRSA.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>

MyRSA::MyRSA() : pkey(nullptr) {
    pkey = EVP_PKEY_new();
}

MyRSA::~MyRSA() {
    EVP_PKEY_free(pkey);
}

void MyRSA::generateKeys() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Keygen init failed" << std::endl;
        return;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "Setting keygen bits failed" << std::endl;
        return;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Keygen failed" << std::endl;
        return;
    }
    EVP_PKEY_CTX_free(ctx);
}

std::string MyRSA::getPublicKey() {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    char* buffer;
    long length = BIO_get_mem_data(bio, &buffer);
    std::string publicKey(buffer, length);
    BIO_free(bio);
    return publicKey;
}

std::string MyRSA::getPrivateKey() {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PKCS8PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char* buffer;
    long length = BIO_get_mem_data(bio, &buffer);
    std::string privateKey(buffer, length);
    BIO_free(bio);
    return privateKey;
}

std::string MyRSA::encrypt(const std::string& publicKey, const std::string& data) {
    BIO* bio = BIO_new_mem_buf(publicKey.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        std::cerr << "Error reading public key" << std::endl;
        return "";
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::cerr << "Error initializing encryption" << std::endl;
        return "";
    }

    size_t encrypted_len;
    if (EVP_PKEY_encrypt(ctx, nullptr, &encrypted_len, (const unsigned char*)data.c_str(), data.length()) <= 0) {
        std::cerr << "Error determining encrypted length" << std::endl;
        return "";
    }

    std::vector<unsigned char> encrypted(encrypted_len);
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &encrypted_len, (const unsigned char*)data.c_str(), data.length()) <= 0) {
        std::cerr << "Error encrypting data" << std::endl;
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);

    return std::string(encrypted.begin(), encrypted.end());
}

std::string MyRSA::decrypt(const std::string& privateKey, const std::string& data) {
    BIO* bio = BIO_new_mem_buf(privateKey.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PKCS8PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        std::cerr << "Error reading private key" << std::endl;
        return "";
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        std::cerr << "Error initializing decryption" << std::endl;
        return "";
    }

    size_t decrypted_len;
    if (EVP_PKEY_decrypt(ctx, nullptr, &decrypted_len, (const unsigned char*)data.c_str(), data.length()) <= 0) {
        std::cerr << "Error determining decrypted length" << std::endl;
        return "";
    }

    std::vector<unsigned char> decrypted(decrypted_len);
    if (EVP_PKEY_decrypt(ctx, decrypted.data(), &decrypted_len, (const unsigned char*)data.c_str(), data.length()) <= 0) {
        std::cerr << "Error decrypting data" << std::endl;
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);

    return std::string(decrypted.begin(), decrypted.end());
}
