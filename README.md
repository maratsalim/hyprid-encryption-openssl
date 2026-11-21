# Hybrid Encryption with OpenSSL (C++)

A homework project for **BIE-KAB (Cryptography and Security)** at the Faculty of Information Technology, Czech Technical University in Prague (summer semester 2025/26). Graded on ProgTest: **5 / 5 points**, passing all tests (valid input, invalid input, memory efficiency, threshold values).

## Why I built it

Real systems such as HTTPS, PGP email encryption and encrypted messengers rarely use just one kind of cipher. They combine two:

- **Symmetric encryption** (e.g. AES) is **fast**, but both sides need the same secret key.
- **Asymmetric encryption** (RSA) solves the key-sharing problem with a public/private key pair, but it is **slow** and works only on small amounts of data.

**Hybrid encryption** takes the best of both: the data is encrypted with a fresh random symmetric key, and only that small key is encrypted with RSA.

The goal of this task was to understand this scheme in practice and to use the **OpenSSL** library correctly: checking every return value, managing resources safely and never leaving broken output files behind.

## What it does

### `seal(inFile, outFile, publicKeyFile, symmetricCipher)`

1. Reads the recipient's RSA **public key**.
2. Generates a random symmetric **key and IV** and encrypts the key with RSA (`EVP_SealInit`).
3. Encrypts the input file with the chosen cipher (for example `aes-128-cbc`), in 4 KiB chunks.
4. Writes the result in this format:

| Offset | Length | Content |
|---|---|---|
| 0 | 4 B | Cipher NID (which symmetric cipher was used) |
| 4 | 4 B | Length of the encrypted key (EKlen) |
| 8 | EKlen B | Symmetric key, encrypted with RSA |
| 8 + EKlen | IVlen B | Initialization vector (if the cipher needs one) |
| 8 + EKlen + IVlen | rest | Encrypted data |

### `open(inFile, outFile, privateKeyFile)`

1. Reads the header and checks it: valid cipher NID, a sensible key length that fits the RSA key.
2. Decrypts the symmetric key with the RSA **private key** (`EVP_OpenInit`).
3. Decrypts the data in chunks and writes the original file.

## Design choices

- **Streaming:** files are processed in 4 KiB blocks, so memory use stays small even for very large files.
- **Automatic cleanup:** OpenSSL keys and contexts are wrapped in `std::unique_ptr` with their free functions, so nothing leaks on any error path.
- **Safe output:** results are written to a temporary file first and renamed only on success. A small RAII helper deletes the temporary file on any failure, so after an error **the output file never exists**, as the assignment requires.
- **Input validation:** a corrupted or fake input file (bad NID, negative or oversized key length, truncated data, wrong private key) is rejected instead of crashing.

## Build and run

```bash
g++ -std=c++20 -Wall hybrid_cipher.cpp -o hybrid_cipher -lcrypto
./hybrid_cipher
```

Requires OpenSSL 3.x. The test `main` expects `PublicKey.pem`, `PrivateKey.pem` and a sample plaintext file in the same folder. You can generate your own key pair with:

```bash
openssl genrsa -out PrivateKey.pem 2048
openssl rsa -in PrivateKey.pem -pubout -out PublicKey.pem
```

## Tech

C++20 · OpenSSL 3 (EVP Seal/Open API, PEM) · RSA + AES · RAII
