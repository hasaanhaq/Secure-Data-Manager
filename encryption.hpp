#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP


#include <openssl/aes.h>     // AES encryption
#include <openssl/evp.h>     // High-level encryption functions
#include <openssl/rand.h>    // Random key/IV generation
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>   
#include <cstring>   
#include <iostream>
using namespace std;


// std::string encryptData(const std::string& plaintext, const std::string& key, const std::string& iv);
// std::string decryptData(const std::string& ciphertext, const std::string& key, const std::string& iv);
// std::string generateKey();
// std::string generateIV();
// std::vector<unsigned char> hexStringToBytes(const std::string& hex);
// std::string bytesToHexString(const std::vector<unsigned char>& bytes);

#endif // ENCRYPTION_HPP
