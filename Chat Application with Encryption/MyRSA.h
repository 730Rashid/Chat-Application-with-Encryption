#ifndef MYRSA_H
#define MYRSA_H

#include <string>
#include <vector>
#include <openssl/evp.h>

class MyRSA {
public:
    MyRSA();
    ~MyRSA();

    void generateKeys();
    std::string getPublicKey();
    std::string getPrivateKey();
    std::string encrypt(const std::string& publicKey, const std::string& data);
    std::string decrypt(const std::string& privateKey, const std::string& data);

private:
    EVP_PKEY* pkey;
};

#endif // MYRSA_H
