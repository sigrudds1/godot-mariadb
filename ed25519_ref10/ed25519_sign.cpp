/*************************************************************************/
/*  ed25519_sign.cpp                                                     */
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
/* https://tools.ietf.org/html/rfc8032#page-44                           */ 

#include "ed25519_auth.h"
#include "ed25519_ge.h"
#include "ed25519_sc.h"

#include <core/os/memory.h>
#include <mbedtls/sha512.h>

void ed25519_sign(const uint8_t *message_src, size_t message_len, const uint8_t *public_key_src, const uint8_t *private_key_src, uint8_t *signature_dst) {
	//message_len should be 32 coming from server

	void *ctx = memalloc(sizeof(mbedtls_sha512_context));
	uint8_t sha512[64];
	uint8_t hram[64];
	ge_p3 R;

	mbedtls_sha512_starts_ret((mbedtls_sha512_context *)ctx, 0);
	mbedtls_sha512_update_ret((mbedtls_sha512_context *)ctx, private_key_src + 32, 32);
	mbedtls_sha512_update_ret((mbedtls_sha512_context *)ctx, message_src, message_len);
	mbedtls_sha512_finish_ret((mbedtls_sha512_context *)ctx, sha512);
	mbedtls_sha512_free((mbedtls_sha512_context *)ctx);

	sc_reduce(sha512);
	ge_scalarmult_base(&R, sha512);
	ge_p3_tobytes(signature_dst, &R);

	mbedtls_sha512_starts_ret((mbedtls_sha512_context *)ctx, 0);
	mbedtls_sha512_update_ret((mbedtls_sha512_context *)ctx, signature_dst, 32);
	mbedtls_sha512_update_ret((mbedtls_sha512_context *)ctx, public_key_src, 32);
	mbedtls_sha512_update_ret((mbedtls_sha512_context *)ctx, message_src, message_len);
	mbedtls_sha512_finish_ret((mbedtls_sha512_context *)ctx, hram);
	mbedtls_sha512_free((mbedtls_sha512_context *)ctx);

	sc_reduce(hram);
	sc_muladd(signature_dst + 32, hram, private_key_src, sha512);

	memfree((mbedtls_sha512_context *)ctx);
}
