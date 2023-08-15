/*************************************************************************/
/*  mariadb_conversions.h                                                        */
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

#ifndef MARIADB_CONVERSIONS_H
#define MARIADB_CONVERSIONS_H

#include <core/io/ip.h>
#include <core/io/ip_address.h>
#include <core/ustring.h>

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <vector>

IP_Address resolve_host(String hostname, IP::Type type);

template <typename T>
T bytes_to_num_itr(const uint8_t *src, const size_t byte_count, size_t &start_pos) {
	size_t count = byte_count;
	T result = 0;

	if (sizeof(T) < byte_count)
		count = sizeof(T);

	for (size_t i = 0; i < count; ++i)
		result |= static_cast<T>(src[++start_pos] << (i * 8));
	return result;
}

template <typename T>
uint8_t *cast_to_uint8_t(const T *ptr) {
	return reinterpret_cast<uint8_t *>(const_cast<char *>(ptr));
}

template <typename T>
std::vector<T> gdstring_to_vector(String string) {
	//T *t = (T *)string.utf8().ptrw(); //breaks after 530ish characters corrupting the end
	//std::vector<T> vec(t, t + string.length());
	std::vector<T> vec;
	for (int i = 0; i < string.length(); i++) {
		vec.push_back(string[i]);
	}
	return vec;
}

template <typename T>
std::vector<T> gd_hexstring_to_vector(const String &hex) {
	std::vector<T> bytes;
	for (size_t i = 0; i < (size_t)hex.length(); i += 2) {
		String byteString = hex.substr(i, 2);
		T byte = (T)strtol(byteString.utf8().ptrw(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

template <typename T>
std::vector<uint8_t> value_to_bytestream_vec(T value, size_t stream_bytes) {
	std::vector<uint8_t> vec;
	for (size_t i = 0; i < stream_bytes; i++) {
		vec.push_back((uint8_t)(value >> (i * 8)) & 0xff);
	}

	return vec;
}

#endif // !MARIADB_CONVERSIONS_H
