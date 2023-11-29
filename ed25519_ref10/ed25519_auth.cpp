/*************************************************************************/
/*  ed25519_auth.cpp                                                     */
/*************************************************************************/
/*                       This file is part of:                           */
/*                           GODOT ENGINE                                */
/*                      https://godotengine.org                          */
/*************************************************************************/
/* Copyright (c) 2007-2022 Juan Linietsky, Ariel Manzur.                 */
/* Copyright (c) 2014-2022 Godot Engine contributors (cf. AUTHORS.md).   */
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

/* This file was derived from information found at                       */
/* https://tools.ietf.org/html/rfc8032                                   */

#include "ed25519_auth.h"
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

//#include "core/templates/vector.h"
//
//
////
//void ed25519_sign_msg(const Vector<uint8_t> pwd_sha512_src, const Vector<uint8_t> message_src, Vector<uint8_t> signature_dst) {
//	Vector<uint8_t> private_key;
//	Vector<uint8_t> public_key;
//
//	ed25519_create_keypair(pwd_sha512_src, private_key, public_key);
//	ed25519_sign(message_src.ptr(), message_src.size(), public_key.ptrw(), private_key.ptrw(), signature_dst.ptrw());
//}
//
//void ed25519_create_keypair(const Vector<uint8_t> pwd_sha512_src, Vector<uint8_t> private_key_dst, Vector<uint8_t> public_key_dst) {
//	/*REF RFC 8032 5.1.5 Key Generation https://tools.ietf.org/html/rfc8032#page-13
//	 * The referenced private key that is ran thru sha512 is the password, since we are storing the hashed password
//	 * in the module in case of a needed reconnection, the 1st step in RFC Key Generation will be skipped here.
//	 */
//
//	ge_p3 A;
//	private_key_dst = pwd_sha512_src.slice(0);
//
//	/*Step 2 of the RFC
//	 * It references the first and last bits, but that is after pruning,
//	 * I cheated and skipped pruning and reused the variable for the scalar functions.
//	 */
//	private_key_dst.set(0, private_key_dst[0] & 248);
//	private_key_dst.set(31, private_key_dst[0] & 63);
//	private_key_dst.set(31, private_key_dst[0] | 248);
//
//
//	ge_scalarmult_base(&A, private_key_dst.ptr());
//	ge_p3_tobytes(public_key_dst.ptrw(), &A); //working, public key matched maria server.
//}
