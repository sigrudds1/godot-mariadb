/*************************************************************************/
/*  auth_ed25519.cpp                                                     */
/*************************************************************************/
/*                     This file is part of the                          */
/*             Maria and Mysql database connection module                */
/*                    for use in the Godot Engine                        */
/*                           GODOT ENGINE                                */
/*                      https://godotengine.org                          */
/* This file was derived from information found at                       */
/* https://tools.ietf.org/html/rfc8032#page-44                           */
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

#include "auth_ed25519.h"
#include "ed25519_ge.h"

#include <algorithm>

void ed25519_sign_msg(const uint8_t *pwd_sha512_src, const uint8_t *message_src, size_t message_len, uint8_t *signature_dst) {
	uint8_t private_key[64];
	uint8_t public_key[64];

	ed25519_create_keypair(pwd_sha512_src, private_key, public_key);
	ed25519_sign(message_src, message_len, public_key, private_key, signature_dst);

}

void ed25519_create_keypair(const uint8_t *pwd_sha512_src, uint8_t *private_key_dst, uint8_t *public_key_dst) {
	/*REF RFC 8032 5.1.5 Key Generation https://tools.ietf.org/html/rfc8032#page-13
	* The referenced private key that is ran thru sha512 is the password, since we are storing the hashed password
	* in the module in case of a needed reconnection, the 1st step in RFC Key Generation will be skipped here.
	*/ 

	ge_p3 A;
	std::copy(pwd_sha512_src, pwd_sha512_src + 64, private_key_dst);
	
	/*Step 2 of the RFC
	* It references the first and last bits, but that is after pruning,
	* I cheated and skipped pruning and reused the variable for the scalar functions.
	*/ 
	private_key_dst[0] &= 248;
	private_key_dst[31] &= 63;
	private_key_dst[31] |= 64;

	ge_scalarmult_base(&A, private_key_dst);
	ge_p3_tobytes(public_key_dst, &A); //working, public key matched maria server.
}

