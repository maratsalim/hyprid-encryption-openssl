#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

using namespace std;

#endif /* __PROGTEST__ */


namespace
{
    struct CleanupFile {
        std::string path;
        bool active = true;
        ~CleanupFile() { 
            if (active && !path.empty()) std::remove(path.c_str()); }
    };

    using EVPKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using EVPCTXPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

    bool writeAll(std::ofstream & os, const void * data, std::streamsize len)
    {
        os.write(reinterpret_cast<const char *>(data), len);
        return os.good();
    }

    bool readAll(std::ifstream & is, void * data, std::streamsize len)
    {
        is.read(reinterpret_cast<char *>(data), len);
        return is.gcount() == len;
    }

    EVPKeyPtr readPublicKey(const std::string & file)
    {
        FILE * fp = std::fopen(file.c_str(), "r");
        if (!fp) return {nullptr, EVP_PKEY_free};
        EVP_PKEY * key = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
        std::fclose(fp);
        return {key, EVP_PKEY_free};
    }

    EVPKeyPtr readPrivateKey(const std::string & file)
    {
        FILE * fp = std::fopen(file.c_str(), "r");
        if (!fp) return {nullptr, EVP_PKEY_free};
        EVP_PKEY * key = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
        std::fclose(fp);
        return {key, EVP_PKEY_free};
    }
}

// Generate random symmetric key + IV
// Encrypt data using symmetric cipher
// Encrypt symmetric key using RSA public key
// Store cipher NID, encrypted key length, encrypted key, IV , ciphertext

int seal(const std::string & inFile, const std::string & outFile, const std::string & publicKeyFile, const std::string & symmetricCipher)
{
    std::remove(outFile.c_str());
    std::string tmpFile = outFile + ".tmp";
    std::remove(tmpFile.c_str());
    CleanupFile tmpCleanup{tmpFile};

    const EVP_CIPHER * cipher = EVP_get_cipherbyname(symmetricCipher.c_str());
    if (!cipher) 
        return EXIT_FAILURE;

    int nid = EVP_CIPHER_nid(cipher);
    if (nid == NID_undef) 
        return EXIT_FAILURE;

    EVPKeyPtr pubKey = readPublicKey(publicKeyFile);
    if (!pubKey) 
        return EXIT_FAILURE;

    std::ifstream in(inFile, std::ios::binary);
    if (!in) 
        return EXIT_FAILURE;

    std::ofstream out(tmpFile, std::ios::binary);
    if (!out) 
        return EXIT_FAILURE;

    EVPCTXPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) 
        return EXIT_FAILURE;

    int maxEkLen = EVP_PKEY_size(pubKey.get());
    if (maxEkLen <= 0) 
        return EXIT_FAILURE;

    std::vector<unsigned char> encryptedKey(maxEkLen);
    std::vector<unsigned char> iv(EVP_CIPHER_iv_length(cipher));

    unsigned char * ekPtr = encryptedKey.data();
    int ekLen = 0;
    EVP_PKEY * keys[1] = { pubKey.get() };

    if (EVP_SealInit(ctx.get(), cipher, &ekPtr, &ekLen, iv.data(), keys, 1) != 1)
        return EXIT_FAILURE;

    if (!writeAll(out, &nid, sizeof(nid))) 
        return EXIT_FAILURE;
    if (!writeAll(out, &ekLen, sizeof(ekLen))) 
        return EXIT_FAILURE;
    if (!writeAll(out, encryptedKey.data(), ekLen)) 
        return EXIT_FAILURE;
    if (!iv.empty() && !writeAll(out, iv.data(), iv.size())) 
        return EXIT_FAILURE;

    std::vector<unsigned char> inBuf(4096);
    std::vector<unsigned char> outBuf(4096 + EVP_CIPHER_block_size(cipher));

    while (in.good()) {
        in.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
        std::streamsize got = in.gcount();

        if (got > 0) {
            int outLen = 0;
            if (EVP_SealUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(got)) != 1)
                return EXIT_FAILURE;

            if (!writeAll(out, outBuf.data(), outLen)) 
                return EXIT_FAILURE;
        }
    }

    if (!in.eof()) 
        return EXIT_FAILURE;

    int finalLen = 0;
    if (EVP_SealFinal(ctx.get(), outBuf.data(), &finalLen) != 1)
        return EXIT_FAILURE;

    if (!writeAll(out, outBuf.data(), finalLen)) 
        return EXIT_FAILURE;

    out.close();
    if (!out) 
        return EXIT_FAILURE;

    std::remove(outFile.c_str());
    if (std::rename(tmpFile.c_str(), outFile.c_str()) != 0)
        return EXIT_FAILURE;

    tmpCleanup.active = false;
    return EXIT_SUCCESS;
}


// Read metadata (cipher, encrypted key, IV)
// Decrypt symmetric key using RSA private key
// Decrypt data using symmetric cipher
int open(const std::string & inFile, const std::string & outFile, const std::string & privateKeyFile)
{
    std::remove(outFile.c_str());
    std::string tmpFile = outFile + ".tmp";
    std::remove(tmpFile.c_str());
    CleanupFile tmpCleanup{tmpFile};

    std::ifstream in(inFile, std::ios::binary);
    if (!in) 
        return EXIT_FAILURE;

    int nid = 0, ekLen = 0;
    if (!readAll(in, &nid, sizeof(nid))) 
        return EXIT_FAILURE;
    if (!readAll(in, &ekLen, sizeof(ekLen))) 
        return EXIT_FAILURE;
    if (ekLen <= 0) 
        return EXIT_FAILURE;

    const EVP_CIPHER * cipher = EVP_get_cipherbynid(nid);
    if (!cipher) 
        return EXIT_FAILURE;

    EVPKeyPtr privKey = readPrivateKey(privateKeyFile);
    if (!privKey) 
        return EXIT_FAILURE;

    if (ekLen > EVP_PKEY_size(privKey.get())) 
        return EXIT_FAILURE;

    std::vector<unsigned char> encryptedKey(ekLen);
    if (!readAll(in, encryptedKey.data(), ekLen)) 
        return EXIT_FAILURE;

    int ivLen = EVP_CIPHER_iv_length(cipher);
    std::vector<unsigned char> iv(ivLen);
    if (ivLen > 0 && !readAll(in, iv.data(), ivLen))
         return EXIT_FAILURE;

    std::ofstream out(tmpFile, std::ios::binary);
    if (!out) 
        return EXIT_FAILURE;

    EVPCTXPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) 
        return EXIT_FAILURE;

    if (EVP_OpenInit(ctx.get(), cipher, encryptedKey.data(), ekLen, iv.empty() ? nullptr : iv.data(), privKey.get()) != 1)
        return EXIT_FAILURE;

    std::vector<unsigned char> inBuf(4096);
    std::vector<unsigned char> outBuf(4096 + EVP_CIPHER_block_size(cipher));

    while (in.good()) {
        in.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
        std::streamsize got = in.gcount();

        if (got > 0) {
            int outLen = 0;
            if (EVP_OpenUpdate(ctx.get(), outBuf.data(), &outLen,
                               inBuf.data(), static_cast<int>(got)) != 1)
                return EXIT_FAILURE;

            if (!writeAll(out, outBuf.data(), outLen)) return EXIT_FAILURE;
        }
    }

    if (!in.eof()) 
        return EXIT_FAILURE;

    int finalLen = 0;
    if (EVP_OpenFinal(ctx.get(), outBuf.data(), &finalLen) != 1)
        return EXIT_FAILURE;

    if (!writeAll(out, outBuf.data(), finalLen)) return EXIT_FAILURE;

    out.close();
    if (!out) 
        return EXIT_FAILURE;

    std::remove(outFile.c_str());
    if (std::rename(tmpFile.c_str(), outFile.c_str()) != 0)
        return EXIT_FAILURE;

    tmpCleanup.active = false;
    return EXIT_SUCCESS;
}

#ifndef __PROGTEST__

int main ( void )
{
    assert(EXIT_SUCCESS == seal("sample_plaintext.txt", "sealed.bin", "PublicKey.pem", "aes-128-cbc") );

    assert(EXIT_SUCCESS == open("sealed.bin", "opened.bin", "PrivateKey.pem") );
    // Verify that opened.bin and sample_plaintext.bin are identical.

    assert(EXIT_SUCCESS == open("sample_ciphertext.bin", "opened.bin", "PrivateKey.pem") );
    // Verify that opened.bin and sample_plaintext.bin are identical.

    return 0;
}

#endif /* __PROGTEST__ */

