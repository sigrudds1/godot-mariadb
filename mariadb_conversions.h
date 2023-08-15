/*************************************************************************/
/*  mariadb_conversions.h                                                        */
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

#ifndef MARIADB_CONVERSIONS_H
#define MARIADB_CONVERSIONS_H

#include <core/io/ip.h>
#include <core/io/ip_address.h>
#include <core/string/ustring.h>

namespace {

	template <typename T>
inline T bytes_to_num_itr_pos(const uint8_t *src, const size_t byte_count, size_t &start_pos) {
	size_t count = byte_count;
	T result = 0;

	if (sizeof(T) < byte_count)
		count = sizeof(T);

	for (size_t i = 0; i < count; ++i)
		result |= static_cast<T>(src[++start_pos]) << (i * 8);
	return result;
}

inline Vector<uint8_t> hex_str_to_v_bytes(const String &hex_str) {
	Vector<uint8_t> bytes;
	for (size_t i = 0; i < (size_t)hex_str.length(); i += 2) {
		String byteString = hex_str.substr(i, 2);
		uint8_t byte = (uint8_t)strtol(byteString.utf8().ptr(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

inline Vector<uint8_t> little_endian_v_bytes(int p_value, size_t p_max_bytes) {
	//little endian bytes
	Vector<uint8_t> vec;
	for (size_t i = 0; i < p_max_bytes; i++) {
		vec.push_back((uint8_t)(p_value >> (i * 8)) & 0xff);
	}

	return vec;
}

} //namespace
#endif // !MARIADB_CONVERSIONS_H
