/*************************************************************************/
/*  mariadb_conversions.h                                                */
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

	if (sizeof(T) < byte_count)
		count = sizeof(T);

	T result = 0;
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

 template <typename T>
inline Vector<uint8_t> little_endian_to_vbytes(const T p_value, const size_t p_max_bytes = 0,
		const size_t p_start_idx = 0) {
	//little endian bytes
	size_t count = sizeof(T);
	if (p_max_bytes > 0 && p_max_bytes <= count)
		count = p_max_bytes;

	Vector<uint8_t> vec;
	for (size_t i = 0 + p_start_idx; i < count + p_start_idx; i++) {
		vec.push_back((uint8_t)(p_value >> (i * 8)) & 0xff);
	}

	return vec;
}

// For testing
// String vbytes_to_int_str(const PackedByteArray p_bytes, String p_delimiter = ",",
// 		int p_out_len = 0, int p_start_idx = 0){
// 	int count = p_bytes.size();
// 	if (p_out_len > count) return "";

// 	if (p_out_len > 0) count = p_out_len + p_start_idx;
// 	String out;
// 	for (int idx = 0 + p_start_idx; idx < count; ++idx) out += itos(p_bytes[idx]) + p_delimiter;

// 	return out;
// }


// TODO DO we need other character sets?
// String vbytes_to_ascii_itr_at(const Vector<uint8_t> &p_src_buf, size_t &p_last_pos, size_t p_byte_cnt) {
// 	String rtn;
// 	for (size_t itr = 0; itr < p_byte_cnt; ++itr)
// 		rtn += p_src_buf[++p_last_pos];

// 	return rtn;
// }

// Thanks @gladman for testing and suggestion
/**
 * \brief			This method returns a string from packets using length encoding.
 *
 * \param src_buf	const Vector<uint8_t> packet buffer.
 * \param last_pos	size_t packet buffer position iterator of the last position used,
 *					this will be incremented by byte count.
 * \param byte_cnt	size_t byte count to be copied from the packet buffer.
 * \return			String.
 */
String vbytes_to_utf8_itr_at(const Vector<uint8_t> &p_src_buf, size_t &p_last_pos, const size_t p_byte_cnt) {
	if (p_byte_cnt <= 0 || p_last_pos + p_byte_cnt > (size_t)p_src_buf.size()){
		return "";
	}

	String rtn_val;
	rtn_val.parse_utf8((const char *)p_src_buf.ptr() + p_last_pos + 1, p_byte_cnt);
	p_last_pos += p_byte_cnt;
	return rtn_val;
}

} //namespace
#endif // !MARIADB_CONVERSIONS_H
