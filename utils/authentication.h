#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <stdint.h>
#include <vector>

std::vector<uint8_t> get_caching_sha2_password_hash(std::vector<uint8_t> sha256_hashed_once_password, std::vector<uint8_t> srvr_salt);

std::vector<uint8_t> get_client_ed25519_signature(std::vector<uint8_t> sha512_hashed_once_password, std::vector<uint8_t> svr_msg);

std::vector<uint8_t> get_mysql_native_password_hash(std::vector<uint8_t> sha1_hashed_once_password, std::vector<uint8_t> srvr_salt);

#endif // !AUTHENTICATION_H
