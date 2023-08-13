/*************************************************************************/
/*  mariadb.cpp                                                          */
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

#include "mariadb.h"

#include "mariadb_auth.h"
//#include "utils/console.h" //removed for iostream removal
#include "conversions.h"
//#include "utils/print_funcs.h"


#include <iostream> //for std::cout Using ERR_FAIL_COND_MSG(false, msg)
//#include <ios>
//#include <algorithm> //remove for Godot usage guidelines no stl
//#include <iterator> //remove for Godot usage guidelines no stl
//#include <string> //remove for Godot usage guidelines no stl

#include "core/os/memory.h"
#include "core/variant/variant.h"
#include <mbedtls/sha512.h>

MariaDB::MariaDB() {
}

MariaDB::~MariaDB() {
	if (is_connected_db()) {
		disconnect_db();
	}
}

//Bind all your methods used in this class
void MariaDB::_bind_methods() {
	ClassDB::bind_method(D_METHOD("connect_db", "hostname", "port", "database", "username", "password", "authtype", "is_prehashed"), 
		&MariaDB::connect_db, DEFVAL(AUTH_TYPE_ED25519), DEFVAL(true));
	ClassDB::bind_method(D_METHOD("disconnect_db"), &MariaDB::disconnect_db);
	ClassDB::bind_method(D_METHOD("get_last_query"), &MariaDB::get_last_query);
	ClassDB::bind_method(D_METHOD("get_last_query_converted"), &MariaDB::get_last_query_converted);
	ClassDB::bind_method(D_METHOD("get_last_response"), &MariaDB::get_last_response);
	ClassDB::bind_method(D_METHOD("get_last_transmitted"), &MariaDB::get_last_transmitted);
	ClassDB::bind_method(D_METHOD("get_data_read_size"), &MariaDB::get_data_read_size);
	ClassDB::bind_method(D_METHOD("is_connected_db"), &MariaDB::is_connected_db);
	ClassDB::bind_method(D_METHOD("set_dbl2string", "is_str"), &MariaDB::set_dbl2string);
	ClassDB::bind_method(D_METHOD("set_db_name", "new_name"), &MariaDB::set_db_name);
	ClassDB::bind_method(D_METHOD("set_data_read_size", "size"), &MariaDB::set_data_read_size, DEFVAL(16384));
	ClassDB::bind_method(D_METHOD("query", "qry_stmt"), &MariaDB::query);

	BIND_ENUM_CONSTANT(IP_TYPE_IPV4);
	BIND_ENUM_CONSTANT(IP_TYPE_IPV6);
	BIND_ENUM_CONSTANT(IP_TYPE_ANY);

	BIND_ENUM_CONSTANT(AUTH_TYPE_MYSQL_NATIVE);
	BIND_ENUM_CONSTANT(AUTH_TYPE_ED25519);
}

//Custom Functions
//private
void MariaDB::m_add_packet_header(Vector<uint8_t> &p_pkt, uint8_t p_pkt_seq) {
	Vector<uint8_t> t = little_endian_v_bytes(p_pkt.size(), 3);
	t.push_back(p_pkt_seq);
	t.append_array(p_pkt);
	p_pkt = t.duplicate();
}

//client protocol 4.1
Error MariaDB::m_client_protocol_v41(const AuthType p_srvr_auth_type, const Vector<uint8_t> p_srvr_salt) {

	Vector<uint8_t> srvr_response;
	Vector<uint8_t> srvr_auth_msg;
	uint8_t seq_num = 0;
	AuthType user_auth_type = AUTH_TYPE_ED25519;

	//Per https://mariadb.com/kb/en/connection/#handshake-response-packet
	//int<4> client capabilities
	_client_capabilities = 0;
	if (_server_capabilities & (uint32_t)Capabilities::CLIENT_MYSQL) {
		_client_capabilities |= (uint32_t)Capabilities::CLIENT_MYSQL;
	}
	//client_capabilities |= (uint32_t)Capabilities::FOUND_ROWS;
	_client_capabilities |= (uint32_t)Capabilities::LONG_FLAG; //??
	if (_server_capabilities & (uint32_t)Capabilities::CONNECT_WITH_DB) {
		_client_capabilities |= (uint32_t)Capabilities::CONNECT_WITH_DB;
	}
	_client_capabilities |= (uint32_t)Capabilities::LOCAL_FILES;
	_client_capabilities |= (uint32_t)Capabilities::CLIENT_PROTOCOL_41;
	_client_capabilities |= (uint32_t)Capabilities::CLIENT_INTERACTIVE;
	_client_capabilities |= (uint32_t)Capabilities::SECURE_CONNECTION;
	_client_capabilities |= (uint32_t)Capabilities::RESERVED2; // Not listed in MariaDB docs but if not set it won't parse the stream correctly

	_client_capabilities |= (uint32_t)Capabilities::MULTI_STATEMENTS;
	_client_capabilities |= (uint32_t)Capabilities::MULTI_RESULTS;
	_client_capabilities |= (uint32_t)Capabilities::PS_MULTI_RESULTS;
	_client_capabilities |= (uint32_t)Capabilities::PLUGIN_AUTH;
	_client_capabilities |= (uint32_t)Capabilities::CAN_HANDLE_EXPIRED_PASSWORDS; //??
	_client_capabilities |= (uint32_t)Capabilities::SESSION_TRACK;
	if (_server_capabilities & (uint32_t)Capabilities::CLIENT_DEPRECATE_EOF) {
		_client_capabilities |= (uint32_t)Capabilities::CLIENT_DEPRECATE_EOF;
	}
	_client_capabilities |= (uint32_t)Capabilities::REMEMBER_OPTIONS; //??
	Vector<uint8_t> send_buffer_vec = little_endian_v_bytes(_client_capabilities, 4);

	//int<4> max packet size
	//temp_vec = little_endian_bytes((uint32_t)0x40000000, 4);
	//send_buffer_vec.insert(send_buffer_vec.end(), temp_vec.begin(), temp_vec.end());
	send_buffer_vec.append_array(little_endian_v_bytes((uint32_t)0x40000000, 4));

	//int<1> client character collation
	send_buffer_vec.push_back(33); //utf8_general_ci

	//string<19> reserved
	//send_buffer_vec.insert(send_buffer_vec.end(), 19, 0);
	Vector<uint8_t> temp_vec;
	temp_vec.resize_zeroed(19);
	send_buffer_vec.append_array(temp_vec);

	//if (!(_server_capabilities & (uint32_t)Capabilities::CLIENT_MYSQL)) {
	//	//int<4> extended client capabilities
	//	send_buffer_vec.insert(send_buffer_vec.end(), 4, 0); //future options
	//} else {
	//	//string<4> reserved
	//	send_buffer_vec.insert(send_buffer_vec.end(), 4, 0);
	//}
	temp_vec.resize_zeroed(4);
	send_buffer_vec.append_array(temp_vec);

	//string<NUL> username
	//send_buffer_vec.insert(send_buffer_vec.end(), _username.begin(), _username.end());
	send_buffer_vec.append_array(_username);
	send_buffer_vec.push_back(0); //NUL terminated

	Vector<uint8_t> auth_response;
	if (p_srvr_auth_type == AUTH_TYPE_MYSQL_NATIVE && (_client_auth_type == AUTH_TYPE_MYSQL_NATIVE))
		auth_response = get_mysql_native_password_hash(_password_hashed, p_srvr_salt);

	//if (server_capabilities & PLUGIN_AUTH_LENENC_CLIENT_DATA)
	//string<lenenc> authentication data
	//else if (server_capabilities & CLIENT_SECURE_CONNECTION) //mysql uses secure connection flag for transactions
	if (!(_server_capabilities & (uint32_t)Capabilities::CLIENT_MYSQL) && (_server_capabilities & (uint32_t)Capabilities::SECURE_CONNECTION)) {
		//int<1> length of authentication response
		send_buffer_vec.push_back((uint8_t)auth_response.size());
		//string<fix> authentication response
		send_buffer_vec.append_array(auth_response);
	} else {
		//else string<NUL> authentication response null ended
		send_buffer_vec.append_array(auth_response);
		send_buffer_vec.push_back(0); //NUL terminated
	}

	//if (server_capabilities & CLIENT_CONNECT_WITH_DB)
	//string<NUL> default database name
	if (_client_capabilities & (uint32_t)Capabilities::CONNECT_WITH_DB) {
		send_buffer_vec.append_array(_dbname);
		send_buffer_vec.push_back(0); //NUL terminated
	}

	//if (server_capabilities & CLIENT_PLUGIN_AUTH)
	//string<NUL> authentication plugin name
	Vector<uint8_t> auth_plugin_name = kAuthTypeNames[(size_t)AUTH_TYPE_MYSQL_NATIVE].to_ascii_buffer();
	send_buffer_vec.append_array(auth_plugin_name);
	send_buffer_vec.push_back(0); //NUL terminated

	//if (server_capabilities & CLIENT_CONNECT_ATTRS)
	//int<lenenc> size of connection attributes
	//while packet has remaining data
	//string<lenenc> key
	//string<lenenc> value

	m_add_packet_header(send_buffer_vec, ++seq_num);

	_stream.put_data(send_buffer_vec.ptr(), send_buffer_vec.size());

	srvr_response = m_recv_data(1000);
	size_t itr = 4;

	if (srvr_response.size() > 0) {
		//4th byte is seq should be 2
		seq_num = srvr_response[3];
		//5th byte is status
		uint8_t status = srvr_response[itr];
		if (status == 0x00) {
			_authenticated = true;
			return Error::OK;
		} else if (status == 0xFE) {
			user_auth_type = m_get_server_auth_type(m_find_vbytes_str_at(srvr_response, itr));
		} else if (status == 0xFF) {
			m_handle_server_error(srvr_response, itr);
			_authenticated = false;
			return Error::ERR_UNAUTHORIZED;
		} else {
			ERR_FAIL_V_MSG(Error::ERR_BUG, "Unhandled response code:" + String::num_uint64(srvr_response[itr], 16, true));
		}
	}

	if (user_auth_type == AUTH_TYPE_ED25519 && _client_auth_type == AUTH_TYPE_ED25519) {
		//srvr_auth_msg.assign(srvr_response.begin() + itr + 1, srvr_response.end());
		srvr_auth_msg.append_array(srvr_response.slice(itr + 1));
		auth_response = get_client_ed25519_signature(_password_hashed, srvr_auth_msg);
		send_buffer_vec = auth_response;
	} else {
		return Error::ERR_INVALID_PARAMETER;
	}

	m_add_packet_header(send_buffer_vec, ++seq_num);
	
	Error err = _stream.put_data(send_buffer_vec.ptr(), send_buffer_vec.size());
	ERR_FAIL_COND_V_MSG(err != Error::OK, err, "Failed to put data!");


	srvr_response = m_recv_data(1000);
	if (srvr_response.size() > 0) {
		//4th byte is seq should be 2
		seq_num = srvr_response[3];
		//5th byte is status
		itr = 4;
		if (srvr_response[itr] == 0x00) {
			_authenticated = true;
		} else if (srvr_response[itr] == 0xFF) {
			m_handle_server_error(srvr_response, itr);
			_authenticated = false;
			return Error::ERR_UNAUTHORIZED;
		} else {
			ERR_FAIL_V_MSG(Error::ERR_BUG, "Unhandled response code:" + String::num_uint64(srvr_response[itr], 16, true));
		}
	}

	return Error::OK;
}

Error MariaDB::m_connect(IPAddress p_ip, int p_port) {
	Error err = _stream.connect_to_host(p_ip, p_port);
	ERR_FAIL_COND_V_MSG(err != Error::OK, err, "Cannot connect to host with IP: " + String(p_ip) + " and port: " + itos(p_port));

	for (size_t i = 0; i < 1000; i++) {
		_stream.poll();
		if (_stream.get_status() == StreamPeerTCP::STATUS_CONNECTED) {
			break;
		} else {
			OS::get_singleton()->delay_usec(1000);
		}
	}

	ERR_FAIL_COND_V_MSG(_stream.get_status() != StreamPeerTCP::STATUS_CONNECTED, Error::ERR_CONNECTION_ERROR,
		"Cannot connect to host with IP: " + String(p_ip) + " and port: " + itos(p_port));

	if (_stream.get_status() != StreamPeerTCP::STATUS_CONNECTED) {
		ERR_FAIL_V_MSG(Error::ERR_CONNECTION_ERROR, "Can't connect to DB server!");
	}
	Vector<uint8_t> recv_buffer = m_recv_data(250);
	//std::cout << "recv_bfr:" << recv_buffer.size() << std::endl;
	if (recv_buffer.size() <= 4) {
		ERR_FAIL_V_MSG(Error::ERR_UNAVAILABLE , "connect: Recv bufffer empty!");
	}

	//per https://mariadb.com/kb/en/connection/
	//The first packet from the server on a connection is a greeting giving/suggesting the requirements to login
	//first 3 bytes are packet length byte[0] + (byte[1]<<8) + (byte[2]<<16)
	uint32_t packet_length = (uint32_t)recv_buffer[0] + ((uint32_t)recv_buffer[1] << 8) + ((uint32_t)recv_buffer[2] << 16);
	//On initial connect the packet length shoudl be 4 byte less than buffer length
	if (packet_length != ((uint32_t)recv_buffer.size() - 4)) {
		ERR_FAIL_V_MSG(Error::FAILED, "Recv bfr does not match expected size!");
	}
	//4th byte is sequence number, increment this when replying with login request, if client starts then start at 0
	if (recv_buffer[3] != 0) {
		ERR_FAIL_V_MSG(Error::FAILED, "Packet sequence error!");
	}

	//5th byte is protocol version, currently only 10 for MariaDB and MySQL v3.21.0+, protocol version 9 for older MySQL versions.
	if (recv_buffer[4] == 10) {
		m_server_init_handshake_v10(recv_buffer);
	} else {
		ERR_FAIL_V_MSG(Error::FAILED, "Protocol version incompatible!");
	}

	return Error::OK;
} //m_connect

Variant MariaDB::m_get_type_data(int p_db_field_type, String p_data) {
	switch (p_db_field_type) {
		case 1: // MYSQL_TYPE_TINY
		case 2: // MYSQL_TYPE_SHORT
		case 3: // MYSQL_TYPE_LONG
		case 8: // MYSQL_TYPE_LONGLONG
			return p_data.to_int();
			break;
		case 0: // MYSQL_TYPE_DECIMAL
		case 4: // MYSQL_TYPE_FLOAT
			return p_data.to_float();
			break;
		case 5: // MYSQL_TYPE_DOUBLE
			if (_dbl_to_string) {
				return p_data;
			} else {
				return p_data.to_float();
			}
			break;
		default:
			return p_data;
	}
	return 0;
}

MariaDB::AuthType MariaDB::m_get_server_auth_type(String p_srvr_auth_name) {
	AuthType server_auth_type = AUTH_TYPE_ED25519;
	if (p_srvr_auth_name == "mysql_native_password") {
		server_auth_type = AUTH_TYPE_MYSQL_NATIVE;
	} else if (p_srvr_auth_name == "client_ed25519") {
		server_auth_type = AUTH_TYPE_ED25519;
	}
	//TODO(sigrudds1) Add cached_sha2 for mysql
	return server_auth_type;
}

Vector<uint8_t> MariaDB::m_recv_data(uint32_t p_timeout) {
	int byte_cnt = 0;
	// int rcvd_bytes = 0;
	Vector<uint8_t> recv_buffer, out_buffer;
	uint64_t start_msec = OS::get_singleton()->get_ticks_msec();
	uint64_t time_lapse = 0;
	bool data_rcvd = false;
	
	while (is_connected_db() && time_lapse < p_timeout) {
		_stream.poll();
		byte_cnt = _stream.get_available_bytes();
		if (byte_cnt > 0) {
			// print_line("byte_cnt:", byte_cnt);
			
			start_msec = OS::get_singleton()->get_ticks_msec();
			// if (byte_cnt >= _data_read_size) print_line("byte_cnt:", byte_cnt);
			// 	byte_cnt = _data_read_size;
			
			recv_buffer.resize(byte_cnt);
			_stream.get_data(recv_buffer.ptrw(), byte_cnt);
			data_rcvd = true;
			
			// _stream.get_partial_data(recv_buffer.ptrw(), byte_cnt, rcvd_bytes);
			// print_line("read parital:", rcvd_bytes, " of:", byte_cnt);
			// if (rcvd_bytes > 0) {
			// 	data_rcvd = false;
				
			// } else {
			// 	data_rcvd = true;
			// }

			out_buffer.append_array(recv_buffer);
			// print_line("tcp read size:", byte_cnt, " out buffer:", out_buffer.size());
		} else if(data_rcvd){
			break;
		}
		time_lapse = OS::get_singleton()->get_ticks_msec() - start_msec;
	}

	return out_buffer;
}

void MariaDB::m_handle_server_error(const Vector<uint8_t> p_src_buffer, size_t &p_last_pos) {
	//REF https://mariadb.com/kb/en/err_packet/
	uint16_t srvr_error_code = (uint16_t)p_src_buffer[++p_last_pos];
	srvr_error_code += (uint16_t)p_src_buffer[++p_last_pos] << 8;
	String msg = "";
	msg += String::num_uint64((uint64_t)srvr_error_code);
	if (srvr_error_code == 0xFFFF) {
		//int<1> stage
		//int<1> max_stage
		//int<3> progress
		//string<lenenc> progress_info
	} else {
		if (p_src_buffer[p_last_pos + 1] == '#') {
			msg += "SQL State:";
			for (size_t itr = 0; itr < 6; ++itr)
				msg += (char)p_src_buffer[++p_last_pos];
			msg += " - ";
			while (p_last_pos < (size_t)p_src_buffer.size() - 1) {
				msg += (char)p_src_buffer[++p_last_pos];
			}
		} else {
			//string<EOF> human - readable error message
			while (p_last_pos < (size_t)p_src_buffer.size() - 1) {
				msg += (char)p_src_buffer[++p_last_pos];
			}
		}
	}
	ERR_FAIL_COND_MSG(false, msg);
}

String MariaDB::m_find_vbytes_str(Vector<uint8_t> p_buf) {
	size_t start_pos = 0;
	return m_find_vbytes_str_at(p_buf, start_pos);
}

String MariaDB::m_find_vbytes_str_at(Vector<uint8_t> p_buf, size_t &p_start_pos) {
	Vector<char> vc;
	while (p_buf[++p_start_pos] != 0 && p_start_pos < (size_t)p_buf.size()) {
		vc.push_back(p_buf[p_start_pos]);
	}
	vc.push_back(0); //for proper char * string convertion
	return (String)vc.ptr();
}

size_t MariaDB::m_decode_pkt_len_at(const Vector<uint8_t> p_src_buf, size_t &p_start_pos) {
	size_t len = (size_t)p_src_buf[p_start_pos];
	len += (size_t)p_src_buf[++p_start_pos] << 8;
	len += (size_t)p_src_buf[++p_start_pos] << 16;
	return len;
}

String MariaDB::m_vbytes_to_str_at(const Vector<uint8_t> &p_src_buf, size_t &p_last_pos, size_t p_byte_cnt) {
	String rtn;
	for (size_t itr = 0; itr < p_byte_cnt; ++itr)
		rtn += p_src_buf[++p_last_pos];

	return rtn;
}

Error MariaDB::m_server_init_handshake_v10(const Vector<uint8_t> &p_src_buffer) {

	Vector<char> v_chr_temp;

	//nul string - read the 5th byte until the first nul(00), this is server version string, it is nul terminated
	size_t pkt_itr = 3;
	_server_ver = "";
	while (p_src_buffer[++pkt_itr] != 0 && pkt_itr < (size_t)p_src_buffer.size()) {
		_server_ver += (char)p_src_buffer[pkt_itr];
	}

	//print_line(_server_ver);

	//4bytes - doesn't appear to be needed.
	pkt_itr += 4;

	//salt part 1 - 8 bytes
	Vector<uint8_t> server_salt;
	for (size_t j = 0; j < 8; j++)
		server_salt.push_back(p_src_buffer[++pkt_itr]);

	//reserved byte
	pkt_itr++;

	_server_capabilities = 0;
	//2bytes -server capabilities part 1
	_server_capabilities = (uint32_t)p_src_buffer[++pkt_itr];
	_server_capabilities += ((uint32_t)p_src_buffer[++pkt_itr]) << 8;

	//1byte - server default collation code
	++pkt_itr;

	//2bytes - Status flags
	//uint16_t status = 0;
	//status = (uint16_t)p_src_buffer[++pkt_itr];
	//status += ((uint16_t)p_src_buffer[++pkt_itr]) << 8;
	pkt_itr += 2;

	//2bytes - server capabilities part 2
	_server_capabilities += ((uint32_t)p_src_buffer[++pkt_itr]) << 16;
	_server_capabilities += ((uint32_t)p_src_buffer[++pkt_itr]) << 24;

	if (!(_server_capabilities & (uint32_t)Capabilities::CLIENT_PROTOCOL_41)) {
		ERR_FAIL_V_MSG(Error::FAILED, "Incompatible authorization protocol!");
	}
	//TODO(sigrudds1) Make auth plugin not required if using ssl/tls
	if (!(_server_capabilities & (uint32_t)Capabilities::PLUGIN_AUTH)) {
		ERR_FAIL_V_MSG(Error::FAILED, "Authorization protocol not set!");
	}

	//1byte - salt length 0 for none
	uint8_t server_salt_length = p_src_buffer[++pkt_itr];

	//6bytes - filler
	pkt_itr += 6;

	//TODO(sigrudds1) Handle MariaDB extended capablities, will have to parse server version string
	//4bytes - filler or server capabilities part 3 (mariadb v10.2 or later) "MariaDB extended capablities"
	pkt_itr += 4;

	//12bytes - salt part 2
	for (size_t j = 0; j < (size_t)std::max(13, server_salt_length - 8); j++)
		server_salt.push_back(p_src_buffer[++pkt_itr]);

	//1byte - reserved
	//nul string - auth plugin name, length = auth plugin string length

	v_chr_temp.clear();
	while (p_src_buffer[++pkt_itr] != 0 && pkt_itr < (size_t)p_src_buffer.size()) {
		v_chr_temp.push_back(p_src_buffer[pkt_itr]);
	}
	v_chr_temp.push_back(0); //for proper char * string convertion

	//determine which auth method the server can use
	AuthType p_srvr_auth_type = m_get_server_auth_type((String)v_chr_temp.ptr());

	return m_client_protocol_v41(p_srvr_auth_type, server_salt);
} //server_init_handshake_v10

void MariaDB::m_update_password(String p_password) {
	if (_is_pre_hashed)
		return;

	//take the password and store it as the hash, only the hash is needed
	if (_client_auth_type == AUTH_TYPE_MYSQL_NATIVE) {
		_password_hashed = p_password.sha1_buffer();
	} else if (_client_auth_type == AUTH_TYPE_ED25519) {
		_password_hashed.resize(64);
		void *ctx = memalloc(sizeof(mbedtls_sha512_context));
		mbedtls_sha512_init((mbedtls_sha512_context *)ctx);
		mbedtls_sha512_starts_ret((mbedtls_sha512_context *)ctx, 0);
		mbedtls_sha512_update_ret((mbedtls_sha512_context *)ctx, (uint8_t *)p_password.ascii().ptr(), p_password.length());
		mbedtls_sha512_finish_ret((mbedtls_sha512_context *)ctx, _password_hashed.ptrw());
		mbedtls_sha512_free((mbedtls_sha512_context *)ctx);
		memfree((mbedtls_sha512_context *)ctx);
	}

	//TODO(sigrudds1) mysql caching_sha2_password
}

void MariaDB::m_update_username(String p_username) {
	_username = p_username.to_ascii_buffer();
}

//public
Error MariaDB::connect_db(String p_host, int p_port, String p_dbname, String p_username, String p_hashed_password,
		AuthType p_authtype, bool p_is_prehashed) {

	IPAddress ip;

	if (p_host.is_valid_ip_address()) {
		ip = p_host;
	} else {
		ip = IP::get_singleton()->resolve_hostname(p_host, (IP::Type)_ip_type);
	}

	disconnect_db();
	_client_auth_type = p_authtype;
	_is_pre_hashed = p_is_prehashed;
	

	if (p_username.size() <= 0) {
		ERR_PRINT("username not set");
		return Error::ERR_INVALID_PARAMETER;
	}

	if (p_hashed_password.size() <= 0) {
		ERR_PRINT("password not set");
		return Error::ERR_INVALID_PARAMETER;
	}

	if (p_dbname.length() <= 0 && _client_capabilities & (uint32_t)Capabilities::CONNECT_WITH_DB) {
		ERR_PRINT("dbname not set");
		return Error::ERR_INVALID_PARAMETER;
	} else {
		set_db_name(p_dbname);
	}

	m_update_username(p_username);

	if (p_is_prehashed) {
		_password_hashed = hex_str_to_v_bytes(p_hashed_password);
	} else {
		m_update_password(p_hashed_password);
	}

	return m_connect(ip, p_port);
}

void MariaDB::disconnect_db() {
	_stream.poll();
	if (is_connected_db()) {
		//say goodbye too the server
		uint8_t output[5] = { 0x01, 0x00, 0x00, 0x00, 0x01 };
		_stream.put_data(output, 5);
		_stream.disconnect_from_host();
	}
	_authenticated = false;
}

String MariaDB::get_last_query() {
	return _last_query;
}

PackedByteArray MariaDB::get_last_query_converted() {
	return _last_query_converted;
}

PackedByteArray MariaDB::get_last_response() {
	return _last_response;
}

PackedByteArray MariaDB::get_last_transmitted() {
	return _last_transmitted;
}

int MariaDB::get_data_read_size() {
	return	_data_read_size;
}

bool MariaDB::is_connected_db() {
	_stream.poll();
	return _stream.get_status() == StreamPeerTCP::STATUS_CONNECTED;
}

Variant MariaDB::query(String sql_stmt) {
	bool connected = is_connected_db();
	if (!connected)
		return (uint32_t)ERR_NOT_CONNECTED;
	if (!_authenticated)
		return (uint32_t)ERR_AUTH_FAILED;

	_last_query = sql_stmt;
	Vector<uint8_t> send_buffer_vec;
	Vector<uint8_t> srvr_response;
	size_t srvr_response_size = 0;
	
	size_t pkt_itr = 0;
	size_t pkt_len; //techinically section length everything arrives in one stream packet
	size_t len_encode = 0;
	bool done = false;
	bool dep_eof = (_client_capabilities & (uint32_t)Capabilities::CLIENT_DEPRECATE_EOF);

	Vector<ColumnData> col_data;

	send_buffer_vec.push_back(0x03);
	_last_query_converted = sql_stmt.to_ascii_buffer();
	send_buffer_vec.append_array(_last_query_converted);
	m_add_packet_header(send_buffer_vec, 0);

	_last_transmitted = send_buffer_vec;
	_stream.put_data(send_buffer_vec.ptr(), send_buffer_vec.size());

	srvr_response = m_recv_data(1000);
	srvr_response_size = (size_t)srvr_response.size();
	// TODO - Check size
	
	pkt_len = m_decode_pkt_len_at(srvr_response, pkt_itr);
	// print_line(pkt_len);
	//uint8_t seq_num = srvr_response[++pkt_itr];
	++pkt_itr;

	//https://mariadb.com/kb/en/result-set-packets/
	//	Resultset metadata
	//	1 Column count packet
	uint64_t col_cnt = 0;
	uint8_t test = srvr_response[pkt_itr + 1];
	if (test == 0xFF) {
		++pkt_itr;
		int err = srvr_response[pkt_itr + 1] + (srvr_response[pkt_itr + 2] << 8);
		m_handle_server_error(srvr_response, pkt_itr);
		return err;
	} else if (test == 0xFE) {
		col_cnt = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 8, pkt_itr);
	} else if (test == 0xFD) {
		col_cnt = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 3, pkt_itr);
	} else if (test == 0xFC) {
		col_cnt = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 2, pkt_itr);
	} else if (test == 0xFB) {
		//null value
		//TODO(sigrudds1) needs investigation, not sure why this would happen
	} else if (test == 0x00) {
		return 0;
	} else {
		col_cnt = srvr_response[++pkt_itr];
	}

	//	for each column (i.e column_count times)
	for (size_t itr = 0; itr < col_cnt; ++itr) {
		pkt_len = m_decode_pkt_len_at(srvr_response, ++pkt_itr);

		//seq_num = srvr_response[++pkt_itr];
		++pkt_itr;

		//		Column Definition packet

		//		string<lenenc> catalog (always 'def')
		len_encode = srvr_response[++pkt_itr];
		m_vbytes_to_str_at(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> schema (database name)
		len_encode = srvr_response[++pkt_itr];
		m_vbytes_to_str_at(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> table alias
		len_encode = srvr_response[++pkt_itr];
		m_vbytes_to_str_at(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> table
		len_encode = srvr_response[++pkt_itr];
		m_vbytes_to_str_at(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> column alias
		len_encode = srvr_response[++pkt_itr];
		String column_name = m_vbytes_to_str_at(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> column
		len_encode = srvr_response[++pkt_itr];
		m_vbytes_to_str_at(srvr_response, pkt_itr, len_encode);

		//TODO(sigrudds1) Enter column name and data type into vector of structs, the column name will be dictionary keynames

		//TODO(sigrudds1) Handle "MariaDB extended capablities" (several locations)
		//		if extended type supported (see MARIADB_CLIENT_EXTENDED_TYPE_INFO )
		//			int<lenenc> length extended info
		//			loop
		//				int<1> data type: 0x00:type, 0x01: format
		//				string<lenenc> value

		//		int<lenenc> length of fixed fields (=0xC)

		++pkt_itr; //remaining bytes in packet section

		//		int<2> character set number
		uint16_t char_set = bytes_to_num_itr_pos<uint16_t>(srvr_response.ptr(), 2, pkt_itr);
		//		int<4> max. column size the number in parenthesis eg int(10), varchar(255)
		//uint32_t col_size = bytes_to_num_itr<uint32_t>(srvr_response.data(), 4, pkt_itr);
		pkt_itr += 4;
		//		int<1> Field types
		uint8_t field_type = srvr_response[++pkt_itr];
		//		int<2> Field detail flag
		pkt_itr += 2;
		//		int<1> decimals
		pkt_itr += 1;
		//		int<2> - unused -
		pkt_itr += 2;

		col_data.push_back({ column_name, char_set, field_type });
	}

	//	if not (CLIENT_DEPRECATE_EOF capability set)
	//		EOF_Packet
	if (!dep_eof) {
		pkt_itr += 5; //bypass for now
	}

	Array arr;
	//process values
	while (!done && pkt_itr < srvr_response_size) {
		if (pkt_itr + 2 >= srvr_response_size) {
			srvr_response.append_array(m_recv_data(100));
			srvr_response_size = (size_t)srvr_response.size();
		}
		pkt_len = m_decode_pkt_len_at(srvr_response, ++pkt_itr);
		//seq_num = srvr_response[++pkt_itr];
		++pkt_itr;

		Dictionary dict;

		for (size_t itr = 0; itr < col_cnt; ++itr) {
			if (pkt_itr + 1 >= srvr_response_size) {
				srvr_response.append_array(m_recv_data(100));
				srvr_response_size = (size_t)srvr_response.size();
			}
			test = srvr_response[pkt_itr + 1];
			if (test == 0xFF) {
				if (pkt_itr + 3 >= srvr_response_size) {
					srvr_response.append_array(m_recv_data(100));
					srvr_response_size = (size_t)srvr_response.size();
				}
				//ERR_Packet
				int err = srvr_response[pkt_itr + 2] + (srvr_response[pkt_itr + 3] << 8);
				m_handle_server_error(srvr_response, pkt_itr);
				done = true;
				return err;
			} else if ((test == 0x00 && dep_eof /* && pkt_len < 0xFFFFFF */) ||
					(test == 0xFE && dep_eof && pkt_len < 0xFFFFFF)) {
				//OK_Packet
				done = true;
			} else if (test == 0xFE && pkt_len < 0xFFFFFF && !dep_eof) {
				//EOF_Packet
				done = true;
			} else {
				if (test == 0xFE) {
					if (pkt_itr + 8 >= srvr_response_size) {
						srvr_response.append_array(m_recv_data(100));
						srvr_response_size = (size_t)srvr_response.size();
					}
					len_encode = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 8, pkt_itr);
				} else if (col_cnt == 0xFD) {
					if (pkt_itr + 3 >= srvr_response_size) {
						srvr_response.append_array(m_recv_data(100));
						srvr_response_size = (size_t)srvr_response.size();
					}

					len_encode = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 3, pkt_itr);
				} else if (col_cnt == 0xFC) {
					if (pkt_itr + 2 >= srvr_response_size) {
						srvr_response.append_array(m_recv_data(100));
						srvr_response_size = (size_t)srvr_response.size();
					}

					len_encode = bytes_to_num_itr_pos<uint64_t>(srvr_response.ptr(), 2, pkt_itr);
				} else if (test == 0xFB) {
					//null value need to skip
					len_encode = 0;
					++pkt_itr;
				} else {
					if (pkt_itr + 1 > (size_t)srvr_response.size())	srvr_response.append_array(m_recv_data(100));
					len_encode = srvr_response[++pkt_itr];
				}

				if (len_encode > 0) {
					if (pkt_itr + len_encode >= srvr_response_size) {
						srvr_response.append_array(m_recv_data(100));
						srvr_response_size = (size_t)srvr_response.size();
					}
					dict[col_data[itr].name] = m_get_type_data(col_data[itr].field_type,
							m_vbytes_to_str_at(srvr_response, pkt_itr, len_encode));
				} else {
					dict[col_data[itr].name] = Variant();
				}
			}
		}
		// print_line(pkt_itr, " size:", srvr_response.size());
		if (!done)
			arr.push_back(dict);
	}
	return Variant(arr);
}

void MariaDB::set_dbl2string(bool p_set_string) {
	_dbl_to_string = p_set_string;
}

void MariaDB::set_db_name(String p_dbname) {
	//_dbname = gdstring_to_vector<uint8_t>(p_dbname);
	_dbname = p_dbname.to_ascii_buffer();
	//TODO(sigrudds1) If db is not the same and connected then change db on server
}

void MariaDB::set_ip_type(IpType p_type) {
	_ip_type = p_type;
}

void MariaDB::set_data_read_size(int p_size) {
	if (p_size > 128 && p_size <= 0xffffff)
		_data_read_size = p_size;
}
