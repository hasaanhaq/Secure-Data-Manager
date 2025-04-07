# 🔐 Secure Data Manager

The **Secure Data Manager** is a C++ project designed to safely encrypt and decrypt sensitive client data using **OpenSSL**. This system is built to manage confidential records such as names and personal IDs, ensuring secure file storage and future compatibility with cloud-based databases such as **AWS DynamoDB** or **S3**.

---

## 🚀 Project Goals

- **Encryption & Decryption**  
  Secure all data at rest using **AES-256-CBC encryption** via OpenSSL, with support for line-by-line encryption and decryption.

- **File-Based Storage (Current)**  
  Encrypt and store records locally in a file-friendly base64 format. A **plaintext file** is processed into an **encrypted output file**, which can later be decrypted back to match the original.

- **Modular Code Architecture**
  - `encryption.hpp/.cpp`: Handles all cryptographic logic.
  - `filehandler.cpp`: Manages reading, encrypting, writing, and decrypting from files.

- **CLI-Based Interface (Upcoming)**  
  A menu-driven interface for:
  - Encrypting a file
  - Decrypting a file
  - Viewing individual records

- **Cloud-Ready Design**  
  While the current focus is on file-based systems, the project is being designed with future **cloud integration in mind**. The goal is to store encrypted data in services like:
  - **AWS S3** for secure object storage
  - **AWS DynamoDB** for fast, scalable access to encrypted records
  - **AWS KMS** (Key Management Service) for future secure key storage

---

## 🛠 Technologies & Tools

| Tech             | Purpose                                  |
|------------------|------------------------------------------|
| **C++17**         | Core language for system implementation |
| **OpenSSL**       | Encryption and base64 encoding           |
| **AWS (Planned)** | Cloud storage and key management         |
| **HTML/CSS/JS**   | Future web-based interface               |

---

## ✅ Current Features

- [x] AES-256-CBC encryption using OpenSSL
- [x] IV prepending + base64 encoding for file-safe storage
- [x] Decryption logic to validate encrypted file integrity
- [x] End-to-end testing: `data.txt` → `encrypted.txt` → `decrypted.txt`

---

## 🧪 How It Works

1. Input: Plaintext file `data.txt`  
2. Each line is encrypted, IV-prepended, and base64-encoded  
3. Output: Encrypted file `encrypted.txt`  
4. Decryption reads `encrypted.txt`, extracts IV, decrypts data, and writes it to `decrypted.txt`  
5. ✅ If `decrypted.txt` matches `data.txt`, you're good!

---

## 🎯 Future Enhancements

- [ ] Add file-based decryption function
- [ ] Implement CLI menu system
- [ ] Abstract encryption key/IV management for better reuse
- [ ] Cloud storage with AWS S3 or DynamoDB
- [ ] Secure key management via AWS KMS or custom vault
- [ ] Unit + integration testing
- [ ] Web-based frontend interface using HTML/CSS/JS

---

## 📌 Why This Project?

This project offers hands-on experience with:
- Modern C++ practices
- Practical cryptography with OpenSSL
- Secure data handling
- File I/O and base64 transformations
- Laying groundwork for **cloud-native applications**

---

## 📅 Roadmap

| Stage                      | Status   |
|---------------------------|----------|
| C++ encryption logic      | ✅ Done   |
| File-based encryption     | ✅ Done   |
| File-based decryption     | 🔄 In Progress |
| CLI menu system           | 🔜 Next Step |
| Cloud integration (AWS)   | 🔜 Future |
| Web frontend              | 🔜 Future |

---

This README will continue to evolve as the project grows. Thanks for checking it out! 🚀
