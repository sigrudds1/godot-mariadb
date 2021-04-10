/*************************************************************************/
/*  mariadb.cpp                                                          */
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

#include "mariadb.h"

#include "utils/authentication.h"
#include "utils/console.h"
#include "utils/conversions.h"
#include "utils/print_funcs.h"

#include <iostream>//for std::cout
#include <algorithm>
#include <iterator>

#include <core/os/memory.h>
#include <mbedtls/sha512.h>

MariaDB::MariaDB() {
}

MariaDB::~MariaDB() {
	//close the connection
	if (stream_.is_connected_to_host()) {
		//let the server know we are discconnecting and disconnect
		disconnect_db();
	}
}

//Bind all your methods used in this class
void MariaDB::_bind_methods() {
	ClassDB::bind_method(D_METHOD("connect_db", "hostname", "port", "database", "username", "password"), &MariaDB::connect_db);
	ClassDB::bind_method(D_METHOD("disconnect_db"), &MariaDB::disconnect_db);
	ClassDB::bind_method(D_METHOD("set_authtype", "auth_src", "auth_type", "is_pre_hashed"), &MariaDB::set_authtype);
	ClassDB::bind_method(D_METHOD("query", "qry_stmt"), &MariaDB::query);

	BIND_ENUM_CONSTANT(AUTH_SRC_CONSOLE);
	BIND_ENUM_CONSTANT(AUTH_SRC_SCRIPT);
	BIND_ENUM_CONSTANT(AUTH_TYPE_MYSQL_NATIVE);
	BIND_ENUM_CONSTANT(AUTH_TYPE_ED25519);
}

//Custom Functions
//private
void MariaDB::m_add_packet_header(std::vector<uint8_t> &stream, int sequence) {
	//need to get buffer length first before adding seq# and length to front of stream
	std::vector<uint8_t> length_bytes = value_to_bytestream_vec(stream.size(), 3);
	stream.insert(stream.begin(), sequence);
	//3 byte - packet length
	stream.insert(stream.begin(), length_bytes.begin(), length_bytes.end());
}

void MariaDB::m_client_protocol_v41(const AuthType srvr_auth_type, const std::vector<uint8_t> srvr_salt) {
	std::vector<uint8_t> send_buffer_vec;
	std::vector<uint8_t> temp_vec;
	std::vector<uint8_t> auth_response;
	std::vector<uint8_t> srvr_response;
	std::vector<uint8_t> srvr_auth_msg;
	uint8_t seq_num = 0;
	AuthType user_auth_type = AUTH_TYPE_UNKNOWN;
	size_t itr = 0;

	//Per https://mariadb.com/kb/en/connection/#handshake-response-packet
	//int<4> client capabilities
	client_capabilities_ = 0;
	if (server_capabilities_ & (uint32_t)Capabilities::MYSQL) {
		client_capabilities_ |= (uint32_t)Capabilities::MYSQL;
	}
	//client_capabilities |= (uint32_t)Capabilities::FOUND_ROWS;
	client_capabilities_ |= (uint32_t)Capabilities::LONG_FLAG; //??
	if (server_capabilities_ & (uint32_t)Capabilities::CONNECT_WITH_DB) {
		client_capabilities_ |= (uint32_t)Capabilities::CONNECT_WITH_DB;
	}
	client_capabilities_ |= (uint32_t)Capabilities::LOCAL_FILES;
	client_capabilities_ |= (uint32_t)Capabilities::PROTOCOL_41;
	client_capabilities_ |= (uint32_t)Capabilities::INTERACTIVE;
	client_capabilities_ |= (uint32_t)Capabilities::SECURE_CONNECTION;
	client_capabilities_ |= (uint32_t)Capabilities::RESERVED2; // Not listed in Maria docs but if not set it won't parse the stream correctly

	client_capabilities_ |= (uint32_t)Capabilities::MULTI_STATEMENTS;
	client_capabilities_ |= (uint32_t)Capabilities::MULTI_RESULTS;
	client_capabilities_ |= (uint32_t)Capabilities::PS_MULTI_RESULTS;
	client_capabilities_ |= (uint32_t)Capabilities::PLUGIN_AUTH;
	client_capabilities_ |= (uint32_t)Capabilities::CAN_HANDLE_EXPIRED_PASSWORDS; //??
	client_capabilities_ |= (uint32_t)Capabilities::SESSION_TRACK;
	if (server_capabilities_ & (uint32_t)Capabilities::DEPRECATE_EOF) {
		client_capabilities_ |= (uint32_t)Capabilities::DEPRECATE_EOF;
	}
	client_capabilities_ |= (uint32_t)Capabilities::REMEMBER_OPTIONS; //??
	send_buffer_vec = value_to_bytestream_vec(client_capabilities_, 4);

	//int<4> max packet size
	temp_vec = value_to_bytestream_vec((uint32_t)0x40000000, 4);
	send_buffer_vec.insert(send_buffer_vec.end(), temp_vec.begin(), temp_vec.end());

	//int<1> client character collation
	send_buffer_vec.push_back(33); //utf8_general_ci

	//string<19> reserved
	send_buffer_vec.insert(send_buffer_vec.end(), 19, 0);

	if (!(server_capabilities_ & (uint32_t)Capabilities::MYSQL)) {
		//int<4> extended client capabilities
		send_buffer_vec.insert(send_buffer_vec.end(), 4, 0); //future options
	} else {
		//string<4> reserved
		send_buffer_vec.insert(send_buffer_vec.end(), 4, 0);
	}

	//string<NUL> username
	send_buffer_vec.insert(send_buffer_vec.end(), username_.begin(), username_.end());
	send_buffer_vec.push_back(0); //NUL terminated

	if (srvr_auth_type == AUTH_TYPE_MYSQL_NATIVE && (client_auth_type_ == AUTH_TYPE_MYSQL_NATIVE))
		auth_response = get_mysql_native_password_hash(password_hashed_, srvr_salt);
	
	//if (server_capabilities & PLUGIN_AUTH_LENENC_CLIENT_DATA)
		//string<lenenc> authentication data
	//else if (server_capabilities & CLIENT_SECURE_CONNECTION) //mysql uses secure connection flag for transactions
	if (!(server_capabilities_ & (uint32_t)Capabilities::MYSQL) && (server_capabilities_ & (uint32_t)Capabilities::SECURE_CONNECTION)) {
		//int<1> length of authentication response
		send_buffer_vec.push_back((uint8_t)auth_response.size());
		//string<fix> authentication response
		send_buffer_vec.insert(send_buffer_vec.end(), auth_response.begin(), auth_response.end()); 
	} else {
		//else string<NUL> authentication response null ended
		send_buffer_vec.insert(send_buffer_vec.end(), auth_response.begin(), auth_response.end());
		send_buffer_vec.push_back(0); //NUL terminated
	}

	//if (server_capabilities & CLIENT_CONNECT_WITH_DB)
	//string<NUL> default database name
	if (client_capabilities_ & (uint32_t)Capabilities::CONNECT_WITH_DB) {
		send_buffer_vec.insert(send_buffer_vec.end(), dbname_.begin(), dbname_.end());
		send_buffer_vec.push_back(0); //NUL terminated
	}

	//if (server_capabilities & CLIENT_PLUGIN_AUTH)
	//string<NUL> authentication plugin name
	std::vector<uint8_t> auth_plugin_name = gdstring_to_vector<uint8_t>(kAuthTypeServerNames[(size_t)AUTH_TYPE_MYSQL_NATIVE]); 
	send_buffer_vec.insert(send_buffer_vec.end(), auth_plugin_name.begin(), auth_plugin_name.end());
	send_buffer_vec.push_back(0); //NUL terminated

	//if (server_capabilities & CLIENT_CONNECT_ATTRS)
	//int<lenenc> size of connection attributes
	//while packet has remaining data
	//string<lenenc> key
	//string<lenenc> value

	m_add_packet_header(send_buffer_vec, ++seq_num);
	stream_.put_data(send_buffer_vec.data(), send_buffer_vec.size());

	srvr_response = m_recv_data(1000);

	if (srvr_response.size() > 0) {
		//4th byte is seq should be 2
		seq_num = srvr_response[3];
		//5th byte is status
		itr = 4;
		if (srvr_response[itr] == 0x00) {
			//std::cout << "response ok" << std::endl;
			authenticated_ = true;
			return;
		} else if (srvr_response[itr] == (uint8_t)0xFE) {
			user_auth_type = m_get_server_auth_type(m_get_gdstring_from_buf(srvr_response, itr));
		} else if (srvr_response[itr] == 0xFF) {
			m_handle_server_error(srvr_response, itr);
			authenticated_ = false;
			return;
		} else {
			std::cout << "unhandled response code:" << std::hex << srvr_response[itr] << std::endl;
			user_auth_type = AUTH_TYPE_UNKNOWN;
		}
	}
	
	if (user_auth_type == AUTH_TYPE_ED25519 && client_auth_type_ == AUTH_TYPE_ED25519) {
		srvr_auth_msg.assign(srvr_response.begin() + itr + 1, srvr_response.end());
		auth_response = get_client_ed25519_signature(password_hashed_,srvr_auth_msg);
		send_buffer_vec = auth_response;
	} else {
		error_ |= (size_t)ErrorCodes::AUTH_PLUGIN_INCOMPATIBLE;
		return;
	}

	m_add_packet_header(send_buffer_vec, ++seq_num);
	stream_.put_data(send_buffer_vec.data(), send_buffer_vec.size());

	srvr_response = m_recv_data(1000);
	if (srvr_response.size() > 0) {
		//4th byte is seq should be 2
		seq_num = srvr_response[3];
		//5th byte is status
		itr = 4;
		if (srvr_response[itr] == 0x00) {
			authenticated_ = true;
			return;
		} else if (srvr_response[itr] == 0xFF) {
			m_handle_server_error(srvr_response, itr);
			error_ |= (size_t)ErrorCodes::AUTH_FAILED;
			authenticated_ = false;
		} else {
			std::cout << "unhandled response code:" << std::hex << srvr_response[itr] << std::endl;
		}
	}
}

int MariaDB::m_connect(String hostname, int port) {
	error_ = 0;
	stream_.connect_to_host(hostname, port);
	connected_ = stream_.is_connected_to_host();

	std::vector<uint8_t> recv_buffer = m_recv_data(250);

	//per https://mariadb.com/kb/en/connection/
	//The first packet from the server on a connection is a greeting giving/suggesting the requirements to login
	//first 3 bytes are packet length byte[0] + (byte[1]<<8) + (byte[2]<<16)
	uint32_t packet_length = 0;
	packet_length =  (uint32_t)recv_buffer[0] + ((uint32_t)recv_buffer[1] << 8) + ((uint32_t)recv_buffer[2] << 16);
	//4th byte is sequence number, increment this when replying with login request, if client starts then start at 0
	uint8_t sequence_number = recv_buffer[3];

	//if (packet_length == byte_cnt - 4 && sequence_number != 0) continue;

	//5th byte is protocol version, currently only 10 for MariaDB and MySQL v3.21.0+, protocol version 9 for older MySQL versions.
	if (recv_buffer[4] == 10) {
		m_server_init_handshake_v10(recv_buffer);
	} else {
		error_ |= (size_t)ErrorCodes::SERVER_PROTOCOL_INCOMPATIBLE;
	}
	return error_;
} //m_connect

MariaDB::AuthType MariaDB::m_get_server_auth_type(String srvr_auth_name) {
	AuthType server_auth_type = AUTH_TYPE_UNKNOWN;
	if (srvr_auth_name == "mysql_native_password") {
		server_auth_type = AUTH_TYPE_MYSQL_NATIVE;
	} else if (srvr_auth_name == "client_ed25519") {
		server_auth_type = AUTH_TYPE_ED25519;
	}
	//TODO(sigrud) Add cached_sha2 for mysql 
	return server_auth_type;
}

std::vector<uint8_t> MariaDB::m_recv_data(uint32_t timeout) {
	int byte_cnt = 0;
	uint8_t *recv_buffer = (uint8_t *)memalloc(32);
	bool replied = false;
	uint32_t start_msec = OS::get_singleton()->get_ticks_msec();

	while (!replied && (connected_ = stream_.is_connected_to_host()) && OS::get_singleton()->get_ticks_msec() - start_msec < timeout) {
		byte_cnt = stream_.get_available_bytes();
		if (byte_cnt > 0) {
			start_msec = OS::get_singleton()->get_ticks_msec();
			if (byte_cnt > kPacketMaxSize) byte_cnt = kPacketMaxSize;
			recv_buffer = (uint8_t *)memrealloc(recv_buffer, static_cast<size_t>(byte_cnt) + 1);
			stream_.get_data(recv_buffer, byte_cnt);
			replied = true;
		}
	}

	std::vector<uint8_t> return_vec(recv_buffer, recv_buffer + byte_cnt);
	memfree(recv_buffer);
	return return_vec;
}

void MariaDB::m_print_error(std::string error) {
	std::cout << error << std::endl;
}

void MariaDB::m_handle_server_error(const std::vector<uint8_t> src_buffer, size_t &last_pos) {
	//REF https://mariadb.com/kb/en/err_packet/
	uint16_t srvr_error_code = (uint16_t)src_buffer[++last_pos];
	srvr_error_code += (uint16_t)src_buffer[++last_pos] << 8;
	std::string msg = "Error Code:";
	msg += std::to_string((uint32_t)srvr_error_code);
	if (srvr_error_code == 0xFFFF) {
		//int<1> stage
		//int<1> max_stage
		//int<3> progress
		//string<lenenc> progress_info
	} else {
		if (src_buffer[last_pos + 1] == '#') {
			msg += " - SQL State:";
			for (size_t itr = 0; itr < 6; ++itr)
				msg += (char)src_buffer[++last_pos];
			msg += " - ";
			while (last_pos < src_buffer.size() - 1) {
				msg += (char)src_buffer[++last_pos];
			}
		} else {
			//string<EOF> human - readable error message
			msg += " - ";
			while (last_pos < src_buffer.size() - 1) {
				msg += (char)src_buffer[++last_pos];
			}
		}
	}
	m_print_error(msg);

}

String MariaDB::m_get_gdstring_from_buf(std::vector<uint8_t> buf, size_t &start_pos) {
	Vector<char> v_chr_temp;
	while (buf[++start_pos] != 0 && start_pos < buf.size()) {
		v_chr_temp.push_back(buf[start_pos]);
	}
	v_chr_temp.push_back(0); //for proper char * string convertion
	return (String)v_chr_temp.ptr();
}

size_t MariaDB::m_get_packet_length(const std::vector<uint8_t> src_buf, size_t &start_pos) {
	size_t pkt_sz = (size_t)src_buf[start_pos];
	pkt_sz += (size_t)src_buf[++start_pos] << 8;
	pkt_sz += (size_t)src_buf[++start_pos] << 16;
	return pkt_sz;
}

std::vector<uint8_t> MariaDB::m_get_password_hash(const AuthType authtype) {
	std::vector<uint8_t> password_hash;

	return password_hash;
}

std::string MariaDB::m_get_packet_string(const std::vector<uint8_t> src_buf, size_t &last_pos, size_t byte_cnt) {
	std::string result;
	for (size_t itr = 0; itr < byte_cnt; ++itr)
		result += src_buf[++last_pos];

	return result;
}

void MariaDB::m_server_init_handshake_v10(const std::vector<uint8_t> src_buffer) {
	uint32_t connection_id = {};
	uint16_t status = 0;

	std::vector<uint8_t> server_salt;
	Vector<char> v_chr_temp;

	//nul string - read the 6th byte until the first nul(00), this is server version string, it is nul terminated
	size_t itr = 4;
	while (src_buffer[++itr] != 0 && itr < src_buffer.size()) {
		v_chr_temp.push_back(src_buffer[itr]);
	}
	v_chr_temp.push_back(0);
	server_version_ = v_chr_temp.ptr();

	//4bytes - from server version string nul +1, doesn't appear to be needed.
	connection_id = bytes_to_num<uint32_t>(src_buffer.data(), 4, itr);

	//salt part 1
	for (size_t j = 0; j < 8; j++)
		server_salt.push_back(src_buffer[++itr]);

	//reserved byte
	itr++;

	server_capabilities_ = 0;
	//2bytes -server capabilities part 1
	server_capabilities_ = (uint32_t)src_buffer[++itr];
	server_capabilities_ += ((uint32_t)src_buffer[++itr]) << 8;
	
	//1byte - server default collation code
	uint8_t collation_code = src_buffer[++itr];

	//2bytes - Status flags
	status = (uint16_t)src_buffer[++itr];
	status += ((uint16_t)src_buffer[++itr]) << 8;

	//2bytes - server capabilities part 2
	server_capabilities_ += ((uint32_t)src_buffer[++itr]) << 16;
	server_capabilities_ += ((uint32_t)src_buffer[++itr]) << 24;

	error_ |= (server_capabilities_ & (uint32_t)Capabilities::PROTOCOL_41) ? 0 : (uint32_t)ErrorCodes::CLIENT_PROTOCOL_INCOMPATIBLE;
	//TODO(sigrud) Make auth plugin not required if using ssl/tls
	error_ |= (server_capabilities_ & (uint32_t)Capabilities::PLUGIN_AUTH) ? 0 : (uint32_t)ErrorCodes::AUTH_PLUGIN_NOT_SET;

	//1byte - salt length 0 for none
	uint8_t server_salt_length = src_buffer[++itr];

	//6bytes - filler
	itr += 6;

	//TODO(sigrud) Handle MariaDB extended capablities, will have to parse server version string
	
	//4bytes - filler or server capabilities part 3 (mariadb v10.2 or later) "MariaDB extended capablities"
	itr += 4;
	//12bytes - salt part 2
	for (size_t j = 0; j < std::max(13, server_salt_length - 8); j++)
		server_salt.push_back(src_buffer[++itr]);

	server_salt.pop_back(); //remove the last element 

	//1byte - reserved
	//i++;
	//nul string - auth plugin name, length = auth plugin string length
	v_chr_temp.clear();
	while (src_buffer[++itr] != 0 && itr < src_buffer.size()) {
		v_chr_temp.push_back(src_buffer[itr]);
	}
	v_chr_temp.push_back(0); //for proper char * string convertion

	//determine which auth method the server can use
	AuthType srvr_auth_type = m_get_server_auth_type((String)v_chr_temp.ptr());
	if (srvr_auth_type == AUTH_TYPE_UNKNOWN) {
		error_ |= (uint32_t)ErrorCodes::AUTH_PLUGIN_INCOMPATIBLE;
	}

	//if not protocol 41 or auth plugin mysql_native_password then exit
	if (error_ == 0) 
		m_client_protocol_v41(srvr_auth_type, server_salt);

	return;
} //server_init_handshake_v10

void MariaDB::m_update_password(String password) {
	if (is_pre_hashed_) return;

	//take the password and store it as the hash, we only need the hash in the algorithms
	if (client_auth_type_ == AUTH_TYPE_MYSQL_NATIVE) {
		uint8_t *sha1 = password.sha1_buffer().ptrw();
		password_hashed_.insert(password_hashed_.end(), sha1, sha1 + 20);
	} else if (client_auth_type_ == AUTH_TYPE_ED25519) {
		uint8_t sha512[64];
		void *ctx = memalloc(sizeof(mbedtls_sha512_context));
		mbedtls_sha512_init((mbedtls_sha512_context *)ctx);
		mbedtls_sha512_starts_ret((mbedtls_sha512_context *)ctx, 0);
		mbedtls_sha512_update_ret((mbedtls_sha512_context *)ctx, (uint8_t *)password.ascii().ptr(), password.length());
		mbedtls_sha512_finish_ret((mbedtls_sha512_context *)ctx, sha512);
		mbedtls_sha512_free((mbedtls_sha512_context *)ctx);
		memfree((mbedtls_sha512_context *)ctx);
		password_hashed_.insert(password_hashed_.end(), sha512, sha512 + 64);
	}

	//TODO(sigrud) mysql caching_sha2_password
	//uint8_t *sha256 = password.sha256_buffer().ptrw();
	//password_.insert(password_.end(), sha256, sha256 + 32);
}

void MariaDB::m_update_username(String username) {
	username_ = gdstring_to_vector<uint8_t>(username);
}

//public
int MariaDB::connect_db(String hostname, int port, String dbname, String username, String password) {

	if (dbname.length() > 0) {
		update_dbname(dbname);
	} else {
		return (int)ErrorCodes::DB_EMPTY;
	}

	if (auth_src_ == AUTH_SRC_UNKNOWN || client_auth_type_ == AUTH_TYPE_UNKNOWN) {
		//assume via script, mysql_native_password and plain password
		auth_src_ = AUTH_SRC_SCRIPT;
		client_auth_type_ = AUTH_TYPE_MYSQL_NATIVE;
		is_pre_hashed_ = false;
	}

	if (auth_src_ == AUTH_SRC_SCRIPT) {
		if (username.length() <= 0) return (int)ErrorCodes::USERNAME_EMPTY;

		if (password.length() <= 0) return (int)ErrorCodes::PASSWORD_EMPTY;

		m_update_username(username);

		if (is_pre_hashed_) {
			password_hashed_ = gd_hexstring_to_vector<uint8_t>(password);
		} else {
			m_update_password(password);
		}
	}

	if (username_.size() <= 0) return (int)ErrorCodes::USERNAME_EMPTY;
	if (password_hashed_.size() <= 0) return (int)ErrorCodes::PASSWORD_EMPTY;

	return m_connect(hostname, port);
}

void MariaDB::disconnect_db() {
	if (stream_.is_connected_to_host()) {
		uint8_t output[6] = { 0x01, 0x00, 0x00, 0x00, 0x01, 0x00 };
		stream_.put_data(output, 6); //say goodbye too the server
		stream_.disconnect_from_host();
	}
	connected_ = false;
	authenticated_ = false;
}

Variant MariaDB::query(String sql_stmt) {

	if (!authenticated_) return 1045;

	std::vector<uint8_t> send_buffer_vec;
	std::vector<uint8_t> srvr_response;
	std::vector<uint8_t> temp = gdstring_to_vector<uint8_t>(sql_stmt);

	size_t pkt_itr = 0;
	size_t pkt_len = 0; //techinically section length everything arrives in one stream packet
	uint8_t seq_num = 0;
	uint64_t col_cnt = 0;
	size_t len_encode = 0;
	bool done = false;
	bool dep_eof = (client_capabilities_ & (uint32_t)Capabilities::DEPRECATE_EOF);

	std::vector<ColumnData> col_data;

	send_buffer_vec.push_back(0x03);
	send_buffer_vec.insert(send_buffer_vec.end(), temp.begin(), temp.end());
	m_add_packet_header(send_buffer_vec, 0);
	stream_.put_data(send_buffer_vec.data(), send_buffer_vec.size());

	srvr_response = m_recv_data(1000);

	pkt_len = m_get_packet_length(srvr_response, pkt_itr);
	seq_num = srvr_response[++pkt_itr];

	//https://mariadb.com/kb/en/result-set-packets/
	//	Resultset metadata
	//	1 Column count packet
	col_cnt = srvr_response[++pkt_itr];
	if (col_cnt == 0xFF) {
		int err = srvr_response[pkt_itr + 1] + (srvr_response[pkt_itr + 2] << 8);
		m_handle_server_error(srvr_response, pkt_itr);
		return err;
	} else if (col_cnt == 0xFE) {
		col_cnt = bytes_to_num<uint64_t>(srvr_response.data(), 8, pkt_itr);
	} else if (col_cnt == 0xFD) {
		col_cnt = bytes_to_num<uint64_t>(srvr_response.data(), 3, pkt_itr);
	} else if (col_cnt == 0xFC) {
		col_cnt = bytes_to_num<uint64_t>(srvr_response.data(), 2, pkt_itr);
	} else if (col_cnt == 0xFB) {
		//null value
		//TODO(sigrud) needs investigation, not sure why this would happen
	}

	//	for each column (i.e column_count times)
	for (size_t itr = 0; itr < col_cnt; ++itr) {
		pkt_len = m_get_packet_length(srvr_response, ++pkt_itr);
		seq_num = srvr_response[++pkt_itr];

		//		Column Definition packet

		//		string<lenenc> catalog (always 'def')
		len_encode = srvr_response[++pkt_itr];
		m_get_packet_string(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> schema
		len_encode = srvr_response[++pkt_itr];
		m_get_packet_string(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> table alias
		len_encode = srvr_response[++pkt_itr];
		m_get_packet_string(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> table
		len_encode = srvr_response[++pkt_itr];
		m_get_packet_string(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> column alias
		len_encode = srvr_response[++pkt_itr];
		m_get_packet_string(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> column
		len_encode = srvr_response[++pkt_itr];

		String column_name = (char *)m_get_packet_string(srvr_response, pkt_itr, len_encode).data();

		//TODO(sigrud) Enter column name and data type into vector of structs, the column name will be dictionary keynames

		//TODO(sigrud) Handle "MariaDB extended capablities" (several locations)
		//		if extended type supported (see MARIADB_CLIENT_EXTENDED_TYPE_INFO )
		//			int<lenenc> length extended info
		//			loop
		//				int<1> data type: 0x00:type, 0x01: format
		//				string<lenenc> value

		//		int<lenenc> length of fixed fields (=0xC)

		++pkt_itr; //remaining bytes in packet section

		//		int<2> character set number
		uint16_t char_set = bytes_to_num<uint16_t>(srvr_response.data(), 2, pkt_itr);
		//		int<4> max. column size
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

	while (!done && pkt_itr < srvr_response.size()) {
		pkt_len = m_get_packet_length(srvr_response, ++pkt_itr);
		seq_num = srvr_response[++pkt_itr];
		len_encode = srvr_response[++pkt_itr];

		if (len_encode == 0xFF) {
			//ERR_Packet
			int err = srvr_response[pkt_itr + 1] + (srvr_response[pkt_itr + 2] << 8);
			m_handle_server_error(srvr_response, pkt_itr);
			done = true;
			return err;
		} else if ((len_encode == 0x00 && dep_eof /* && pkt_len < 0xFFFFFF */) ||
				   (len_encode == 0xFE && dep_eof && pkt_len < 0xFFFFFF)) {
			//OK_Packet
			done = true;
		} else if (len_encode == 0xFE && pkt_len < 0xFFFFFF && !dep_eof) {
			//EOF_Packet
			done = true;
		} else {
			Dictionary dict;
			//loop thru column data and create dictionary column name = key value is typed
			//TODO(sigrud) use col_data.field_type to set type value
			dict[col_data[0].name] = m_get_packet_string(srvr_response, pkt_itr, len_encode).c_str();
			for (size_t itr = 1; itr < col_cnt; ++itr) {
				len_encode = srvr_response[++pkt_itr];
				dict[col_data[itr].name] = m_get_packet_string(srvr_response, pkt_itr, len_encode).c_str();
			}
			arr.push_back(dict);
		}

	}

	return Variant(arr);
}

void MariaDB::update_dbname(String dbname) {
	dbname_ = gdstring_to_vector<uint8_t>(dbname);
	//TODO(sigrud) If db is not the same and connected then change db on server
}

int MariaDB::set_authtype(AuthSrc auth_src, AuthType auth_type, bool is_pre_hashed) {
	int err = 0;
	if (auth_src <= AUTH_SRC_UNKNOWN || auth_src >= AUTH_SRC_LAST) {
		std::cout << "MariaDB authentication source not set!" << std::endl;
		return (int)ErrorCodes::AUTH_PLUGIN_NOT_SET;
	}

	if (auth_type <= AUTH_TYPE_UNKNOWN || auth_type >= AUTH_TYPE_LAST) {
		std::cout << "MariaDB authentication type not set!" << std::endl;
		return (int)ErrorCodes::AUTH_PLUGIN_NOT_SET;
	}

	auth_src_ = auth_src;
	client_auth_type_ = auth_type;
	is_pre_hashed_ = is_pre_hashed;
	if (auth_src == AUTH_SRC_CONSOLE) {
		is_pre_hashed_ = false;
		std::cout << "MariaDB Console Authentication Enabled" << std::endl;
		std::cout << "Username:";
		String username = get_gdstring_from_console(true, 10000);

		std::cout << "Password:";
		String password = get_gdstring_from_console(false, 10000);
		std::cout << std::endl;

		m_update_username(username);
		m_update_password(password);
	}

	return err;
}
