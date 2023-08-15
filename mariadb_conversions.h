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

// IP_Address resolve_host(const String hostname, const IP::Type type);
// String vbytes_to_str_at_idx(const Vector<uint8_t> &p_src_buf, size_t &p_last_pos, size_t p_byte_cnt);

inline IP_Address resolve_host(const String hostname, const IP::Type type) {
	IP_Address ip;
	if (hostname.is_valid_ip_address()) {
		ip = hostname;
	} else {
		ip = IP::get_singleton()->resolve_hostname(hostname, type);
	}
	return ip;
}


inline String vbytes_to_str_at_idx(const Vector<uint8_t> &p_src_buf, int &p_last_pos, const int p_byte_cnt){
	String rtn;
	for (int itr = 0; itr < p_byte_cnt; ++itr)
		rtn += p_src_buf[++p_last_pos];

	return rtn;
}

inline PoolByteArray vbytes_to_pba(const Vector<uint8_t> v){
	PoolByteArray pba;
	return pba;
}

	template <typename T>
T bytes_to_num_itr_pos(const uint8_t *src, const int byte_count, int &start_pos) {
	int count = byte_count;
	T result = 0;

	if ((int)sizeof(T) < byte_count)
		count = (int)sizeof(T);

	for (int i = 0; i < count; ++i)
		result |= static_cast<T>(src[++start_pos] << (i * 8));
	return result;
}

template <typename T>
uint8_t *cast_to_uint8_t(const T *ptr) {
	return reinterpret_cast<uint8_t *>(const_cast<char *>(ptr));
}

template <typename T>
Vector<T> gdstring_to_vector(const String string) {
	//T *t = (T *)string.utf8().ptrw(); //breaks after 530ish characters corrupting the end
	//Vector<T> vec(t, t + string.length());
	Vector<T> vec;
	for (int i = 0; i < string.length(); i++) {
		vec.push_back(string[i]);
	}
	return vec;
}

template <typename T>
Vector<T> gd_hexstring_to_vector(const String &hex) {
	Vector<T> bytes;
	for (int i = 0; i < (int)hex.length(); i += 2) {
		String byteString = hex.substr(i, 2);
		T byte = (T)strtol(byteString.utf8().ptrw(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}


inline Vector<uint8_t> le_vector_bytes(const int p_value, const int p_max_bytes) {
	//little endian bytes
	Vector<uint8_t> vec;
	for (int i = 0; i < p_max_bytes; i++) {
		vec.push_back((uint8_t)(p_value >> (i * 8)) & 0xff);
	}

	return vec;
}


#endif // !MARIADB_CONVERSIONS_H
