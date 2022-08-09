/*************************************************************************/
/*  auth_ed25519.h                                                   */
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

#ifndef AUTH_ED25519_H
#define AUTH_ED25519_H

#include <stddef.h>
#include <stdint.h>

//REF https://security.stackexchange.com/questions/218046/how-does-mariadbs-ed25519-auth-scheme-work

void ed25519_sign_msg(const uint8_t *pwd_sha512_src, const uint8_t *message_src, size_t message_len, uint8_t *signature_dst);
void ed25519_create_keypair(const uint8_t *pwd_sha512_src, uint8_t *private_key_dst, uint8_t *public_key_dst);
void ed25519_sign(const uint8_t *message_src, size_t message_len, const uint8_t *public_key_src, const uint8_t *private_key_src, uint8_t *signature_dst);

#endif // !AUTH_ED25519_H
