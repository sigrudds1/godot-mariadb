/*************************************************************************/
/*  mariadb_auth.cpp                                                        */
/*************************************************************************/
/*                     This file is part of the                          */
/*             Maria and Mysql database connection module                */
/*                    for use in the Godot Engine                        */
/*                           GODOT ENGINE                                */
/*                      https://godotengine.org                          */
/*************************************************************************/
/* Copyright (c) 2021 Shawn Shipton. https://vikingtinkerer.com          */
/*                                                                       */
/* Permission is hereby granted, free of charge, to any person obtaining */
/* a copy of this software and associated documentation files (the       */
/* "Software"), to deal in the Software without restriction, including   */
/* without limitation the rights to use, copy, modify, merge, publish,   */
/* distribute, sublicense, and/or sell copies of the Software, and to    */
/* permit persons to whom the Software is furnished to do so, subject to */
/* the following conditions:                                             */
/*                                                                       */
/* The above copyright notice and this permission notice shall be        */
/* included in all copies or substantial portions of the Software.       */
/*                                                                       */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,       */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF    */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.*/
/* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY  */
/* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,  */
/* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE     */
/* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                */
/*************************************************************************/
#include "mariadb_auth.h"

#include "ed25519_ref10/ed25519_auth.h"
#include <core/crypto/crypto_core.h>

std::vector<uint8_t> get_caching_sha2_password_hash(std::vector<uint8_t> sha256_hashed_once_password, std::vector<uint8_t> srvr_salt) {
	//For MySQL compatibility, MariaDB does not support this auth method
	//TODO(sigrudds1) Check validity, there seems to be a discrepency in description between Maria and MySQL and Maria was originally used as ref.
	constexpr int hash_size = 32;
	uint8_t hash[hash_size] = {};
	CryptoCore::sha256(sha256_hashed_once_password.data(), hash_size, hash);
	std::vector<uint8_t> hash_out;
	uint8_t combined_salt_pwd[hash_size * 2] = {};
	for (size_t i = 0; i < hash_size; i++) {
		combined_salt_pwd[i] = srvr_salt[i];
		combined_salt_pwd[i + hash_size] = hash[i];
	}

	CryptoCore::sha256((const uint8_t *)combined_salt_pwd, hash_size * 2, hash);
	for (size_t i = 0; i < hash_size; i++) {
		hash_out.push_back(sha256_hashed_once_password[i] ^ hash[i]);
	}

	return hash_out;
}

std::vector<uint8_t> get_client_ed25519_signature(std::vector<uint8_t> sha512_hashed_once_password, std::vector<uint8_t> svr_msg) {
	//MySQL does not supprt this auth method
	uint8_t signature[64];
	ed25519_sign_msg(sha512_hashed_once_password.data(), svr_msg.data(), 32, signature);
	std::vector<uint8_t> signature_vec(signature, signature + 64);
	return signature_vec;
}

std::vector<uint8_t> get_mysql_native_password_hash(std::vector<uint8_t> sha1_hashed_once_password, std::vector<uint8_t> srvr_salt) {
	//per https://mariadb.com/kb/en/connection/#mysql_native_password-plugin
	//Both MariaDB and MySQL support this auth method
	uint8_t hash[20] = {};

	CryptoCore::sha1(sha1_hashed_once_password.data(), 20, hash);
	std::vector<uint8_t> hash_out;
	uint8_t combined_salt_pwd[40] = {};
	for (size_t i = 0; i < 20; i++) {
		combined_salt_pwd[i] = srvr_salt[i];
		combined_salt_pwd[i + 20] = hash[i];
	}

	CryptoCore::sha1((const uint8_t *)combined_salt_pwd, 40, hash);
	for (size_t i = 0; i < 20; i++) {
		hash_out.push_back(sha1_hashed_once_password[i] ^ hash[i]);
	}

	return hash_out;
}
