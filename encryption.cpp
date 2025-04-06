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
    // unsigned char key[AES_KEY_LENGTH];
    // unsigned char iv[AES_BLOCK_SIZE];

    // Generate random key and IV.
    // Note: In a production system, you should separate key management
    // so that you can decrypt the data later.
    // if (RAND_bytes(key, sizeof(key)) != 1) {
    //     cerr << "Error generating random key" << endl;
    //     return "";
    // }
    // if (RAND_bytes(iv, sizeof(iv)) != 1) {
    //     cerr << "Error generating random IV" << endl;
    //     return "";
    // }

    unsigned char key[AES_KEY_LENGTH] = {
        '0','1','2','3','4','5','6','7',
        '8','9','0','1','2','3','4','5',
        '6','7','8','9','0','1','2','3',
        '4','5','6','7','8','9','0','1'
    };
    
    unsigned char iv[AES_BLOCK_SIZE] = {
        '0','1','2','3','4','5','6','7',
        '8','9','0','1','2','3','4','5'
    };
    


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


std::string base64Decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.data(), encoded.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<unsigned char> decoded(encoded.length()); // max size
    int decodedLength = BIO_read(bio, decoded.data(), encoded.length());
    BIO_free_all(bio);

    return std::string(reinterpret_cast<char*>(decoded.data()), decodedLength);
}

std::string decrypt(const std::string& base64Ciphertext) {
    const int AES_KEY_LENGTH = 32;
    

    // Hardcoded key for testing (must match encryption)
    unsigned char key[AES_KEY_LENGTH] = {
        '0','1','2','3','4','5','6','7',
        '8','9','0','1','2','3','4','5',
        '6','7','8','9','0','1','2','3',
        '4','5','6','7','8','9','0','1'
    };

    std::string decoded = base64Decode(base64Ciphertext);
    if (decoded.length() <= AES_BLOCK_SIZE) {
        std::cerr << "Invalid encrypted input!" << std::endl;
        return "";
    }

    // Extract IV and actual ciphertext
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, decoded.data(), AES_BLOCK_SIZE);
    const unsigned char* ciphertext = reinterpret_cast<const unsigned char*>(decoded.data() + AES_BLOCK_SIZE);
    int ciphertext_len = decoded.length() - AES_BLOCK_SIZE;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create context" << std::endl;
        return "";
    }

    std::vector<unsigned char> plaintext(ciphertext_len + AES_BLOCK_SIZE); // enough space
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        std::cerr << "DecryptInit failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
        std::cerr << "DecryptUpdate failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        std::cerr << "DecryptFinal failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}







#include "encryption.hpp"
#include <fstream>
#include <vector>

int main() {
    const std::string inputFile = "data.txt";
    const std::string encryptedFile = "encrypted.txt";

    std::ifstream inFile(inputFile);
    std::ofstream outFile(encryptedFile);

    if (!inFile.is_open() || !outFile.is_open()) {
        std::cerr << "Failed to open input or output file." << std::endl;
        return 1;
    }

    std::vector<std::string> originalLines;
    std::vector<std::string> encryptedLines;
    std::vector<std::string> decryptedLines;

    std::string line;
    while (std::getline(inFile, line)) {
        originalLines.push_back(line);

        std::string encrypted = encrypt(line);
        encryptedLines.push_back(encrypted);

        outFile << encrypted << '\n';
    }

    inFile.close();
    outFile.close();

    std::cout << "All lines encrypted and written to '" << encryptedFile << "'.\n" << std::endl;

    // Decrypt all encrypted lines and compare with original
    for (size_t i = 0; i < encryptedLines.size(); ++i) {
        std::string decrypted = decrypt(encryptedLines[i]);
        decryptedLines.push_back(decrypted);

        cout << "==== Line " << i + 1 << " ====" << endl;
        cout << "Original : " << originalLines[i] << endl;
        cout << "Encrypted: " << encryptedLines[i] << endl;
        cout << "Decrypted: " << decrypted << endl;

        if (decrypted == originalLines[i]) {
            std::cout << "✅ Match\n" << endl;
        } else {
            std::cout << "❌ Mismatch!\n" << endl;
        }
    }

    return 0;
}

