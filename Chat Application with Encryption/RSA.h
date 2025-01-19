#ifndef RSA_H
#define RSA_H

#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>
#include <iostream>

class RSA {
public:
    // Constructor and Destructor
    RSA();
    ~RSA();

    // Function to generate RSA keys
    void generateKeys();

    // Function to encrypt data
    std::string encrypt(const std::string &data);

    // Function to decrypt data
    std::string decrypt(const std::string &data);

private:
    // RSA private and public keys
    RSA* publicKey;
    RSA* privateKey;
};

#endif // SIMPLERSA_H
