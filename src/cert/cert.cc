#include "cryptix/cert.h"

#include <fstream>
#include <openssl/pem.h>
#include <fmt/core.h>

namespace Cryptix {

Cert::~Cert() {
    if (cert_ != nullptr) {
        ::X509_free(cert_);
    }
}

std::optional<Cert> Cert::FromPemText(std::string_view pemText){
    if (pemText.empty()) {
        fmt::print("{} is empty", pemText);
        return std::nullopt;
    }

    // Create a BIO object to read the PEM data
    UniqueBio bio {::BIO_new_mem_buf(const_cast<char*>(pemText.data()), pemText.size()), ::BIO_free};
    if (!bio) {
        fmt::print("Failed to create BIO object");
        return std::nullopt;
    }
    X509* c = ::PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (c == nullptr) {
        fmt::print("Failed to read from BIO object");
        return std::nullopt;
    }

    Cert cert;
    cert.cert_ = c;
    return cert;
}

std::optional<Cert> Cert::FromPemFile(std::filesystem::path pemFile){
    if (std::filesystem::exists(pemFile) == false) {
        fmt::print("{} not found.", pemFile.string());
        return std::nullopt;
    }

    std::ifstream ifs(pemFile);
    if (!ifs.is_open()) {
        fmt::print("{} open failed.", pemFile.string());
        return std::nullopt;
    }
    std::string pemText((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    return FromPemText(pemText);
}

std::optional<Cert> Cert::FromDerText(std::string_view derText){
    if (derText.empty()) {
        return std::nullopt;
    }

    auto buffer = derText.data();
    X509* c = ::d2i_X509(nullptr, reinterpret_cast<const unsigned char**>(&buffer), derText.size());
    if (c == nullptr) {
        return std::nullopt;
    }
    Cert cert;
    cert.cert_ = c;
    return cert;
}

std::optional<Cert> Cert::FromDerFile(std::filesystem::path derFile){
    if (std::filesystem::exists(derFile) == false) {
        return std::nullopt;
    }
    std::ifstream ifs(derFile, std::ios::binary);
    if (!ifs.is_open()) {
        return std::nullopt;
    }
    std::string derText((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    return FromDerText(derText);
}

Result Cert::ToPemFile(std::filesystem::path pemFile) const{
    if (cert_ == nullptr) {
        return Result::INVALID;
    }

    // Create a BIO object to write the PEM data
    UniqueBio bio {::BIO_new_file(pemFile.c_str(), "w"), ::BIO_free};
    if (!bio) {
        return Result::NULLPTR;
    }

    // Write the certificate to the BIO in PEM format
    if (::PEM_write_bio_X509(bio.get(), cert_) != 1) {
        return Result::FAILURE;
    }

    return Result::SUCCESS;
}

Result Cert::ToDerFile(std::filesystem::path derFile) const{
    if (cert_ == nullptr) {
        return Result::INVALID;
    }

    // Create a BIO object to write the DER data
    UniqueBio bio {::BIO_new_file(derFile.c_str(), "w"), ::BIO_free};
    if (!bio) {
        return Result::NULLPTR;
    }

    // Write the certificate to the BIO in DER format
    if (::i2d_X509_bio(bio.get(), cert_) != 1) {
        return Result::FAILURE;
    }

    return Result::SUCCESS;
}

Result Cert::ToPemText(std::string& pemText) const{
    if (cert_ == nullptr) {
        return Result::INVALID;
    }

    // Create a BIO object to write the PEM data
    UniqueBio bio {::BIO_new(BIO_s_mem()), ::BIO_free};
    if (!bio) {
        return Result::NULLPTR;
    }

    // Write the certificate to the BIO in PEM format
    if (::PEM_write_bio_X509(bio.get(), cert_) != 1) {
        return Result::FAILURE;
    }

    // Get the PEM data from the BIO
    BUF_MEM* bufferPtr;
    ::BIO_get_mem_ptr(bio.get(), &bufferPtr);
    pemText.assign(bufferPtr->data, bufferPtr->length);

    return Result::SUCCESS;
}

Result Cert::ToDerText(std::string& derText) const{
    if (cert_ == nullptr) {
        return Result::INVALID;
    }
    // Create a BIO object to write the DER data
    UniqueBio bio {::BIO_new(BIO_s_mem()), ::BIO_free};
    if (!bio) {
        return Result::NULLPTR;
    }
    // Write the certificate to the BIO in DER format
    if (::i2d_X509_bio(bio.get(), cert_) != 1) {
        return Result::FAILURE;
    }
    // Get the DER data from the BIO
    BUF_MEM* bufferPtr;
    ::BIO_get_mem_ptr(bio.get(), &bufferPtr);
    derText.assign(bufferPtr->data, bufferPtr->length);

    return Result::SUCCESS;
}

}