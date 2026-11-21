# hyprid-encryption-openssl
seal and open files using a random AES key encrypted with RSA (EVP Seal/Open API). Streams data in 4 KiB chunks, validates the file header, uses RAII for OpenSSL resources and never leaves a broken output file on errors.
