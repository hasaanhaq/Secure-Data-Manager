#include "encryption.hpp"


using namespace std;

void copyFile(const string& inputFile, const string& outputFile) {
    ifstream inFile(inputFile);
    ofstream outFile(outputFile);

    if (inFile.is_open() && outFile.is_open()) {
        string line;
        while (getline(inFile, line)) {
            outFile << line << "\n";
        }
        inFile.close();
        outFile.close();
        cout << "File Copy Success!" << endl;
    } else {
        cout << "ERROR opening file!" << endl;
    }
}

const unsigned int AES_KEY_LENGTH = 32;

std::string base64Encode(const unsigned char* buffer, size_t length) {
    BIO* bio = nullptr;
    BIO* b64 = nullptr;
    BUF_MEM* bufferPtr = nullptr;

    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        cerr << "Error initializing BIO_f_base64" << endl;
        return "";
    }
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        cerr << "Error initializing BIO_s_mem" << endl;
        BIO_free(b64);
        return "";
    }
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines

    if (BIO_write(bio, buffer, length) <= 0) {
        cerr << "Error writing to BIO" << endl;
        BIO_free_all(bio);
        return "";
    }
    if (BIO_flush(bio) != 1) {
        cerr << "Error flushing BIO" << endl;
        BIO_free_all(bio);
        return "";
    }
    BIO_get_mem_ptr(bio, &bufferPtr);
    if (!bufferPtr) {
        cerr << "Error retrieving buffer pointer" << endl;
        BIO_free_all(bio);
        return "";
    }
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::string encrypt(const std::string& plaintext) {
    unsigned char key[AES_KEY_LENGTH];
    unsigned char iv[AES_BLOCK_SIZE];

    // Generate random key and IV.
    // Note: In a production system, you should separate key management
    // so that you can decrypt the data later.
    if (RAND_bytes(key, sizeof(key)) != 1) {
        cerr << "Error generating random key" << endl;
        return "";
    }
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        cerr << "Error generating random IV" << endl;
        return "";
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error creating EVP_CIPHER_CTX" << endl;
        return "";
    }
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;

    // Initialize the encryption context using AES-256-CBC.
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        cerr << "Error initializing encryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                          plaintext.size()) != 1) {
        cerr << "Error during encryption update" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        cerr << "Error during encryption finalization" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // Combine IV and ciphertext.
    // The IV is necessary for decryption, so it's prepended to the ciphertext.
    std::vector<unsigned char> ivAndCipher(iv, iv + AES_BLOCK_SIZE);
    ivAndCipher.insert(ivAndCipher.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

    // Base64 encode the combined data.
    return base64Encode(ivAndCipher.data(), ivAndCipher.size());
}

int main() {
    // Copy file from "data.txt" to "output.txt"
    copyFile("data.txt", "output.txt");

    // Example usage of encrypt function.
    std::string plaintext = "Sensitive data that needs encryption.";
    std::string encrypted = encrypt(plaintext);
    if (!encrypted.empty()) {
        cout << "Encrypted data: " << encrypted << endl;
    } else {
        cerr << "Encryption failed." << endl;
    }
    return 0;
}
