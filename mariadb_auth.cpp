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

Vector<uint8_t> get_client_ed25519_signature(Vector<uint8_t> p_sha512_hashed_passwd, Vector<uint8_t> p_svr_msg) {
	//MySQL does not supprt this auth method
	Vector<uint8_t>signature;
	signature.resize(64);
	ed25519_sign_msg(p_sha512_hashed_passwd.ptr(), p_svr_msg.ptr(), 32, signature.ptrw());
	return signature;
}

Vector<uint8_t> get_mysql_native_password_hash(Vector<uint8_t> p_sha1_hashed_passwd, Vector<uint8_t> p_srvr_salt) {
	//per https://mariadb.com/kb/en/connection/#mysql_native_password-plugin
	//Both MariaDB and MySQL support this auth method
	uint8_t hash[20] = {};

	CryptoCore::sha1(p_sha1_hashed_passwd.ptr(), 20, hash);
	Vector<uint8_t> hash_out;
	uint8_t combined_salt_pwd[40] = {};
	for (size_t i = 0; i < 20; i++) {
		combined_salt_pwd[i] = p_srvr_salt[i];
		combined_salt_pwd[i + 20] = hash[i];
	}

	CryptoCore::sha1((const uint8_t *)combined_salt_pwd, 40, hash);
	for (size_t i = 0; i < 20; i++) {
		hash_out.push_back(p_sha1_hashed_passwd[i] ^ hash[i]);
	}

	return hash_out;
}
