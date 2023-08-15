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

/*TODO(Sigrud) Add debug buffer to be fetched wtih methods
 *	Last query statment
 *	Last output to server
 *	Last response string from server
 *	Turn on outputs
 */

#include "mariadb.h"

#include "mariadb_auth.h"
#include "mariadb_conversions.h"

//#include <ios>
#include <algorithm>
#include <iterator>

#include <core/os/memory.h>
#include <core/variant.h>
#include "core/error_macros.h"
#include <mbedtls/sha512.h>

MariaDB::MariaDB() {
}

MariaDB::~MariaDB() {
	//close the connection
	if (_stream.is_connected_to_host()) {
		//let the server know we are discconnecting and disconnect
		disconnect_db();
	}
}

//Bind all your methods used in this class
void MariaDB::_bind_methods() {
	ClassDB::bind_method(D_METHOD("connect_db", "hostname", "port", "database", "username", "password"), &MariaDB::connect_db);
	ClassDB::bind_method(D_METHOD("disconnect_db"), &MariaDB::disconnect_db);
	ClassDB::bind_method(D_METHOD("is_connected_db"), &MariaDB::is_connected_db);
	ClassDB::bind_method(D_METHOD("set_authtype", "auth_src", "auth_type", "is_pre_hashed"), &MariaDB::set_authtype);
	ClassDB::bind_method(D_METHOD("set_dbl2string", "is_str"), &MariaDB::set_dbl2string);
	ClassDB::bind_method(D_METHOD("set_ip_type", "type"), &MariaDB::set_ip_type);
	ClassDB::bind_method(D_METHOD("query", "qry_stmt"), &MariaDB::query);

	BIND_ENUM_CONSTANT(IP_TYPE_IPV4);
	BIND_ENUM_CONSTANT(IP_TYPE_IPV6);
	BIND_ENUM_CONSTANT(IP_TYPE_ANY);

	BIND_ENUM_CONSTANT(AUTH_SRC_UNKNOWN);
	BIND_ENUM_CONSTANT(AUTH_SRC_SCRIPT);
	BIND_ENUM_CONSTANT(AUTH_SRC_CONSOLE);

	BIND_ENUM_CONSTANT(AUTH_TYPE_UNKNOWN);
	BIND_ENUM_CONSTANT(AUTH_TYPE_MYSQL_NATIVE);
	BIND_ENUM_CONSTANT(AUTH_TYPE_ED25519);

	BIND_ENUM_CONSTANT(ERR_NO_ERROR);
	BIND_ENUM_CONSTANT(ERR_NO_RESPONSE);
	BIND_ENUM_CONSTANT(ERR_NOT_CONNECTED);
	BIND_ENUM_CONSTANT(ERR_PACKET_LENGTH_MISMATCH);
	BIND_ENUM_CONSTANT(ERR_PACKET_SEQUENCE_ERROR);
	BIND_ENUM_CONSTANT(ERR_SERVER_PROTOCOL_INCOMPATIBLE);
	BIND_ENUM_CONSTANT(ERR_CLIENT_PROTOCOL_INCOMPATIBLE);
	BIND_ENUM_CONSTANT(ERR_AUTH_PLUGIN_NOT_SET);
	BIND_ENUM_CONSTANT(ERR_AUTH_PLUGIN_INCOMPATIBLE);
	BIND_ENUM_CONSTANT(ERR_AUTH_FAILED);
	BIND_ENUM_CONSTANT(ERR_USERNAME_EMPTY);
	BIND_ENUM_CONSTANT(ERR_PASSWORD_EMPTY);
	BIND_ENUM_CONSTANT(ERR_DB_EMPTY);
}

//Custom Functions
//private
void MariaDB::m_add_packet_header(Vector<uint8_t> &p_pkt, uint8_t p_pkt_seq) {
	Vector<uint8_t> t = le_vector_bytes(p_pkt.size(), 3);
	t.push_back(p_pkt_seq);
	t.append_array(p_pkt);
	p_pkt = t.to_byte_array();
}

void MariaDB::m_client_protocol_v41(const AuthType srvr_auth_type, const Vector<uint8_t> srvr_salt) {
	Vector<uint8_t> send_buffer_vec;
	Vector<uint8_t> temp_vec;
	Vector<uint8_t> auth_response;
	Vector<uint8_t> srvr_response;
	Vector<uint8_t> srvr_auth_msg;
	uint8_t seq_num = 0;
	AuthType user_auth_type = AUTH_TYPE_UNKNOWN;
	int itr = 0;

	//Per https://mariadb.com/kb/en/connection/#handshake-response-packet
	//int<4> client capabilities
	_client_capabilities = 0;
	if (_server_capabilities & (uint32_t)Capabilities::MYSQL) {
		_client_capabilities |= (uint32_t)Capabilities::MYSQL;
	}
	//client_capabilities |= (uint32_t)Capabilities::FOUND_ROWS;
	_client_capabilities |= (uint32_t)Capabilities::LONG_FLAG; //??
	if (_server_capabilities & (uint32_t)Capabilities::CONNECT_WITH_DB) {
		_client_capabilities |= (uint32_t)Capabilities::CONNECT_WITH_DB;
	}
	_client_capabilities |= (uint32_t)Capabilities::LOCAL_FILES;
	_client_capabilities |= (uint32_t)Capabilities::CLIENT_PROTOCOL_41;
	_client_capabilities |= (uint32_t)Capabilities::INTERACTIVE;
	_client_capabilities |= (uint32_t)Capabilities::SECURE_CONNECTION;
	_client_capabilities |= (uint32_t)Capabilities::RESERVED2; // Not listed in Maria docs but if not set it won't parse the stream correctly

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
	send_buffer_vec = le_vector_bytes(_client_capabilities, 4);

	// //int<4> max packet size
	// temp_vec = le_vector_bytes((uint32_t)0x40000000, 4);
	// send_buffer_vec.insert(send_buffer_vec.end(), temp_vec.begin(), temp_vec.end());
	send_buffer_vec.append_array(le_vector_bytes((uint32_t)0x40000000, 4));

	//int<1> client character collation
	send_buffer_vec.push_back(33); //utf8_general_ci

	//string<19> reserved
	//send_buffer_vec.insert(send_buffer_vec.end(), 19, 0);
	temp_vec.resize(19);
	temp_vec.fill(0);
	send_buffer_vec.append_array(temp_vec);

	// if (!(_server_capabilities & (uint32_t)Capabilities::MYSQL)) {
	// 	//int<4> extended client capabilities
	// 	send_buffer_vec.insert(send_buffer_vec.end(), 4, 0); //future options
	// } else {
	// 	//string<4> reserved
	// 	send_buffer_vec.insert(send_buffer_vec.end(), 4, 0);
	// }
	temp_vec.resize(4);
	temp_vec.fill(0);
	send_buffer_vec.append_array(temp_vec);

	//string<NUL> username
	send_buffer_vec.append_array(username_);
	send_buffer_vec.push_back(0); //NUL terminated

	if (srvr_auth_type == AUTH_TYPE_MYSQL_NATIVE && (_client_auth_type  == AUTH_TYPE_MYSQL_NATIVE))
		auth_response = get_mysql_native_password_hash(_password_hashed, srvr_salt);

	//if (server_capabilities & PLUGIN_AUTH_LENENC_CLIENT_DATA)
	//string<lenenc> authentication data
	//else if (server_capabilities & CLIENT_SECURE_CONNECTION) //mysql uses secure connection flag for transactions
	if (!(_server_capabilities & (uint32_t)Capabilities::MYSQL) && (_server_capabilities & (uint32_t)Capabilities::SECURE_CONNECTION)) {
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
	Vector<uint8_t> auth_plugin_name = gdstring_to_vector<uint8_t>(kAuthTypeServerNames[(int)AUTH_TYPE_MYSQL_NATIVE]);
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

	if (srvr_response.size() > 0) {
		//4th byte is seq should be 2
		seq_num = srvr_response[3];
		//5th byte is status
		itr = 4;
		if (srvr_response[itr] == 0x00) {
			//std::cout << "response ok" << std::endl;
			_authenticated = true;
			return;
		} else if (srvr_response[itr] == (uint8_t)0xFE) {
			user_auth_type = m_get_server_auth_type(m_get_gdstring_from_buf(srvr_response, itr));
		} else if (srvr_response[itr] == 0xFF) {
			m_handle_server_error(srvr_response, itr);
			_authenticated = false;
			error_ |= (int)ERR_AUTH_FAILED;
			return;
		} else {
			user_auth_type = AUTH_TYPE_UNKNOWN;
		}
	}

	if (user_auth_type == AUTH_TYPE_ED25519 && _client_auth_type  == AUTH_TYPE_ED25519) {
		srvr_auth_msg.append_array(srvr_response.slice(itr + 1));
		auth_response = get_client_ed25519_signature(_password_hashed, srvr_auth_msg);
		send_buffer_vec = auth_response;
	} else {
		error_ |= (int)ERR_AUTH_PLUGIN_INCOMPATIBLE;
		return;
	}

	m_add_packet_header(send_buffer_vec, ++seq_num);
	_stream.put_data(send_buffer_vec.ptr(), send_buffer_vec.size());

	srvr_response = m_recv_data(1000);
	if (srvr_response.size() > 0) {
		//4th byte is seq should be 2
		seq_num = srvr_response[3];
		//5th byte is status
		itr = 4;
		if (srvr_response[itr] == 0x00) {
			_authenticated = true;
			return;
		} else if (srvr_response[itr] == 0xFF) {
			m_handle_server_error(srvr_response, itr);
			error_ |= (int)ERR_AUTH_FAILED;
			_authenticated = false;
		}
	}
}

void MariaDB::m_connect(IP_Address ip, int port) {
	error_ = 0;
	_stream.connect_to_host(ip, port);

	Vector<uint8_t> recv_buffer = m_recv_data(250);
	if (recv_buffer.size() <= 4) {
		error_ = (uint32_t)ERR_NO_RESPONSE;
		return;
	}

	//per https://mariadb.com/kb/en/connection/
	//The first packet from the server on a connection is a greeting giving/suggesting the requirements to login
	//first 3 bytes are packet length byte[0] + (byte[1]<<8) + (byte[2]<<16)
	int packet_length = (int)recv_buffer[0] + ((int)recv_buffer[1] << 8) + ((int)recv_buffer[2] << 16);
	//On initial connect the packet length shoudl be 4 byte less than buffer length
	if (packet_length != (recv_buffer.size() - 4)) {
		error_ = (uint32_t)ERR_PACKET_LENGTH_MISMATCH;
		return;
	}
	//4th byte is sequence number, increment this when replying with login request, if client starts then start at 0
	if (recv_buffer[3] != 0) {
		error_ = (uint32_t)ERR_PACKET_SEQUENCE_ERROR;
		return;
	}

	//5th byte is protocol version, currently only 10 for MariaDB and MySQL v3.21.0+, protocol version 9 for older MySQL versions.
	if (recv_buffer[4] == 10) {
		m_server_init_handshake_v10(recv_buffer);
	} else {
		error_ = (uint32_t)ERR_SERVER_PROTOCOL_INCOMPATIBLE;
	}
} //m_connect


int MariaDB::m_dec_3byte_pkt_len_at(const Vector<uint8_t> p_src_buf, int &p_start_pos) {
	int len = (int)p_src_buf[p_start_pos];
	len += (int)p_src_buf[++p_start_pos] << 8;
	len += (int)p_src_buf[++p_start_pos] << 16;
	return len;
}


Variant MariaDB::m_get_gd_type_data(const int db_field_type, const String data) {
	switch (db_field_type) {
		case 1: // MYSQL_TYPE_TINY
		case 2: // MYSQL_TYPE_SHORT
		case 3: // MYSQL_TYPE_LONG
		case 8: // MYSQL_TYPE_LONGLONG
			return data.to_int();
			break;
		case 0: // MYSQL_TYPE_DECIMAL
		case 4: // MYSQL_TYPE_FLOAT
			return data.to_float();
			break;
		case 5: // MYSQL_TYPE_DOUBLE
			if (dbl_to_string_) {
				return data;
			} else {
				return data.to_double();
			}
			break;
		default:
			return data;
	}
	return 0;
}

MariaDB::AuthType MariaDB::m_get_server_auth_type(String srvr_auth_name) {
	AuthType server_auth_type = AUTH_TYPE_UNKNOWN;
	if (srvr_auth_name == "mysql_native_password") {
		server_auth_type = AUTH_TYPE_MYSQL_NATIVE;
	} else if (srvr_auth_name == "client_ed25519") {
		server_auth_type = AUTH_TYPE_ED25519;
	}
	//TODO(sigrudds1) Add cached_sha2 for mysql
	return server_auth_type;
}

Vector<uint8_t> MariaDB::m_recv_data(int p_timeout) {
	int byte_cnt = 0;
	// int rcvd_bytes = 0;
	Vector<uint8_t> recv_buffer, out_buffer;
	int start_msec = OS::get_singleton()->get_ticks_msec();
	int time_lapse = 0;
	bool data_rcvd = false;
	
	while (is_connected_db() && time_lapse < p_timeout) {
		byte_cnt = _stream.get_available_bytes();
		if (byte_cnt > 0) {
			recv_buffer.resize(byte_cnt);
			_stream.get_data(recv_buffer.ptrw(), byte_cnt);
			data_rcvd = true;
			out_buffer.append_array(recv_buffer);
			start_msec = OS::get_singleton()->get_ticks_msec();
		} else if(data_rcvd){
			break;
		}
		time_lapse = OS::get_singleton()->get_ticks_msec() - start_msec;
	}

	return out_buffer;
}


void MariaDB::m_handle_server_error(const Vector<uint8_t> src_buffer, int &last_pos) {
	//REF https://mariadb.com/kb/en/err_packet/
	uint16_t srvr_error_code = (uint16_t)src_buffer[++last_pos];
	srvr_error_code += (uint16_t)src_buffer[++last_pos] << 8;
	String msg = "Error Code:";
	msg += srvr_error_code;
	if (srvr_error_code == 0xFFFF) {
		//int<1> stage
		//int<1> max_stage
		//int<3> progress
		//string<lenenc> progress_info
	} else {
		if (src_buffer[last_pos + 1] == '#') {
			msg += " - SQL State:";
			for (int itr = 0; itr < 6; ++itr)
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
	print_line(msg);
}

String MariaDB::m_get_gdstring_from_buf(Vector<uint8_t> buf) {
	int start_pos = 0;
	return m_get_gdstring_from_buf(buf, start_pos);
}

String MariaDB::m_get_gdstring_from_buf(Vector<uint8_t> buf, int &start_pos) {
	Vector<char> v_chr_temp;
	while (buf[++start_pos] != 0 && start_pos < buf.size()) {
		v_chr_temp.push_back(buf[start_pos]);
	}
	v_chr_temp.push_back(0); //for proper char * string convertion
	return (String)v_chr_temp.ptr();
}

int MariaDB::m_get_packet_length(const Vector<uint8_t> src_buf, int &start_pos) {
	int pkt_sz = (int)src_buf[start_pos];
	pkt_sz += (int)src_buf[++start_pos] << 8;
	pkt_sz += (int)src_buf[++start_pos] << 16;
	return pkt_sz;
}

Vector<uint8_t> MariaDB::m_get_password_hash(const AuthType authtype) {
	Vector<uint8_t> password_hash;

	return password_hash;
}

String MariaDB::m_get_packet_string(const Vector<uint8_t> &src_buf, int &last_pos, const int byte_cnt) {
	String result;
	for (int itr = 0; itr < byte_cnt; ++itr)
		result += src_buf[++last_pos];

	return result;
}

void MariaDB::m_server_init_handshake_v10(const Vector<uint8_t> &p_src_buffer) {

	Vector<char> v_chr_temp;

	//nul string - read the 5th byte until the first nul(00), this is server version string, it is nul terminated
	int pkt_itr = 3;
	_server_ver = "";
	while (p_src_buffer[++pkt_itr] != 0 && pkt_itr < (int)p_src_buffer.size()) {
		_server_ver += (char)p_src_buffer[pkt_itr];
	}

	//print_line(_server_ver);

	//4bytes - doesn't appear to be needed.
	pkt_itr += 4;

	//salt part 1 - 8 bytes
	Vector<uint8_t> server_salt;
	for (int j = 0; j < 8; j++)
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

	// if (!(_server_capabilities & (uint32_t)Capabilities::CLIENT_PROTOCOL_41)) {
	// 	ERR_FAIL_V_MSG(FAILED, "Incompatible authorization protocol!");
	// }
	// //TODO(sigrudds1) Make auth plugin not required if using ssl/tls
	// if (!(_server_capabilities & (uint32_t)Capabilities::PLUGIN_AUTH)) {
	// 	ERR_FAIL_V_MSG(FAILED, "Authorization protocol not set!");
	// }

	//1byte - salt length 0 for none
	uint8_t server_salt_length = p_src_buffer[++pkt_itr];

	//6bytes - filler
	pkt_itr += 6;

	//TODO(sigrudds1) Handle MariaDB extended capablities, will have to parse server version string
	//4bytes - filler or server capabilities part 3 (mariadb v10.2 or later) "MariaDB extended capablities"
	pkt_itr += 4;

	//12bytes - salt part 2
	for (int j = 0; j < (int)std::max(13, server_salt_length - 8); j++)
		server_salt.push_back(p_src_buffer[++pkt_itr]);

	//1byte - reserved
	//nul string - auth plugin name, length = auth plugin string length

	v_chr_temp.clear();
	while (p_src_buffer[++pkt_itr] != 0 && pkt_itr < (int)p_src_buffer.size()) {
		v_chr_temp.push_back(p_src_buffer[pkt_itr]);
	}
	v_chr_temp.push_back(0); //for proper char * string convertion

	//determine which auth method the server can use
	AuthType p_srvr_auth_type = m_get_server_auth_type((String)v_chr_temp.ptr());

	m_client_protocol_v41(p_srvr_auth_type, server_salt);
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

void MariaDB::m_update_username(String username) {
	username_ = gdstring_to_vector<uint8_t>(username);
}

//public
uint32_t MariaDB::connect_db(String hostname, int port, String dbname, String username, String password) {
	if (_stream.is_connected_to_host()) {
		disconnect_db();
	}

	IP_Address ip = resolve_host(hostname, (IP::Type)ip_type_);
	//std::cout << (ip.is_ipv4() ? "ipv4" : "ipv6") << std::endl;

	if (dbname.length() > 0) {
		update_dbname(dbname);
	} else {
		return (int)ERR_DB_EMPTY;
	}

	if (auth_src_ == AUTH_SRC_UNKNOWN || _client_auth_type  == AUTH_TYPE_UNKNOWN) {
		//assume via script, mysql_native_password and plain password
		auth_src_ = AUTH_SRC_SCRIPT;
		_client_auth_type  = AUTH_TYPE_MYSQL_NATIVE;
		_is_pre_hashed  = false;
	}

	if (auth_src_ == AUTH_SRC_SCRIPT) {
		if (username.length() <= 0)
			return (int)ERR_USERNAME_EMPTY;

		if (password.length() <= 0)
			return (int)ERR_PASSWORD_EMPTY;

		m_update_username(username);

		if (_is_pre_hashed ) {
			_password_hashed = gd_hexstring_to_vector<uint8_t>(password);
		} else {
			m_update_password(password);
		}
	}

	if (username_.size() <= 0)
		return (int)ERR_USERNAME_EMPTY;
	if (_password_hashed.size() <= 0)
		return (int)ERR_PASSWORD_EMPTY;

	m_connect(ip, port);
	return error_;
}

void MariaDB::disconnect_db() {
	if (_stream.is_connected_to_host()) {
		uint8_t output[5] = { 0x01, 0x00, 0x00, 0x00, 0x01 };
		_stream.put_data(output, 5); //say goodbye too the server
		_stream.disconnect_from_host();
	}
	_authenticated = false;
}


bool MariaDB::is_connected_db() {
	return _stream.is_connected_to_host();
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
	
	int pkt_itr = 0;
	int pkt_len; //techinically section length everything arrives in one stream packet
	int len_encode = 0;
	bool done = false;
	bool dep_eof = (_client_capabilities & (uint32_t)Capabilities::CLIENT_DEPRECATE_EOF);

	Vector<ColumnData> col_data;

	send_buffer_vec.push_back(0x03);
	send_buffer_vec.append_array(gdstring_to_vector<uint8_t>(sql_stmt));
	m_add_packet_header(send_buffer_vec, 0);

	_last_transmitted = send_buffer_vec;
	_stream.put_data(send_buffer_vec.ptr(), send_buffer_vec.size());

	srvr_response = m_recv_data(1000);
	// TODO - Check size
	
	pkt_len = m_dec_3byte_pkt_len_at(srvr_response, pkt_itr);
	// print_line(pkt_len);
	//uint8_t seq_num = srvr_response[++pkt_itr];
	++pkt_itr;

	//https://mariadb.com/kb/en/result-set-packets/
	//	Resultset metadata
	//	1 Column count packet
	int col_cnt = 0;
	uint8_t test = srvr_response[pkt_itr + 1];
	if (test == 0xFF) {
		++pkt_itr;
		int err = srvr_response[pkt_itr + 1] + (srvr_response[pkt_itr + 2] << 8);
		m_handle_server_error(srvr_response, pkt_itr);
		return err;
	} else if (test == 0xFE) {
		col_cnt = bytes_to_num_itr_pos<int>(srvr_response.ptr(), 8, pkt_itr);
	} else if (test == 0xFD) {
		col_cnt = bytes_to_num_itr_pos<int>(srvr_response.ptr(), 3, pkt_itr);
	} else if (test == 0xFC) {
		col_cnt = bytes_to_num_itr_pos<int>(srvr_response.ptr(), 2, pkt_itr);
	} else if (test == 0xFB) {
		//null value
		//TODO(sigrudds1) needs investigation, not sure why this would happen
	} else if (test == 0x00) {
		return 0;
	} else {
		col_cnt = srvr_response[++pkt_itr];
	}

	//	for each column (i.e column_count times)
	for (int itr = 0; itr < col_cnt; ++itr) {
		pkt_len = m_dec_3byte_pkt_len_at(srvr_response, ++pkt_itr);

		//seq_num = srvr_response[++pkt_itr];
		++pkt_itr;

		//		Column Definition packet

		//		string<lenenc> catalog (always 'def')
		len_encode = srvr_response[++pkt_itr];
		vbytes_to_str_at_idx(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> schema (database name)
		len_encode = srvr_response[++pkt_itr];
		vbytes_to_str_at_idx(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> table alias
		len_encode = srvr_response[++pkt_itr];
		vbytes_to_str_at_idx(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> table
		len_encode = srvr_response[++pkt_itr];
		vbytes_to_str_at_idx(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> column alias
		len_encode = srvr_response[++pkt_itr];
		String column_name = vbytes_to_str_at_idx(srvr_response, pkt_itr, len_encode);

		//		string<lenenc> column
		len_encode = srvr_response[++pkt_itr];
		vbytes_to_str_at_idx(srvr_response, pkt_itr, len_encode);

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
		// 		uint32_t col_size = bytes_to_num_itr<uint32_t>(srvr_response.data(), 4, pkt_itr);
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
	while (!done && pkt_itr < (int)srvr_response.size()) {
		if (pkt_itr + 3 >= (int)srvr_response.size()) {
			srvr_response.append_array(m_recv_data(1000));
		}
		
		pkt_len = m_dec_3byte_pkt_len_at(srvr_response, ++pkt_itr);
		if (pkt_itr + pkt_len >= (int)srvr_response.size()) {
				srvr_response.append_array(m_recv_data(1000));
		}

		//seq_num = srvr_response[++pkt_itr];
		++pkt_itr;

		Dictionary dict;
		for (int itr = 0; itr < col_cnt; ++itr) {
			test = srvr_response[pkt_itr + 1];
			if (test == 0xFF) {
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
					len_encode = bytes_to_num_itr_pos<int>(srvr_response.ptr(), 8, pkt_itr);
				} else if (col_cnt == 0xFD) {
					len_encode = bytes_to_num_itr_pos<int>(srvr_response.ptr(), 3, pkt_itr);
				} else if (col_cnt == 0xFC) {
					len_encode = bytes_to_num_itr_pos<int>(srvr_response.ptr(), 2, pkt_itr);
				} else if (test == 0xFB) {
					//null value need to skip
					len_encode = 0;
					++pkt_itr;
				} else {
					len_encode = srvr_response[++pkt_itr];
				}

				if (len_encode > 0) {
					if (pkt_itr + len_encode >= (int)srvr_response.size()) {
						srvr_response.append_array(m_recv_data(1000));
					}
					dict[col_data[itr].name] = m_get_gd_type_data(col_data[itr].field_type,
							vbytes_to_str_at_idx(srvr_response, pkt_itr, len_encode));
				} else {
					dict[col_data[itr].name] = Variant();
				}
			}
		}
		if (!done)
			arr.push_back(dict);
	}
	return Variant(arr);
}

void MariaDB::update_dbname(String dbname) {
	_dbname = gdstring_to_vector<uint8_t>(dbname);
	//TODO(sigrudds1) If db is not the same and connected then change db on server
}

uint32_t MariaDB::set_authtype(AuthSrc p_auth_src, AuthType p_auth_type, bool p_is_pre_hashed) {
	auth_src_ = p_auth_src;
	_client_auth_type  = p_auth_type;
	_is_pre_hashed  = p_is_pre_hashed;

	return (uint32_t)ERR_NO_ERROR;
}

void MariaDB::set_dbl2string(bool set_string) {
	dbl_to_string_ = set_string;
}

void MariaDB::set_ip_type(IpType type) {
	ip_type_ = type;
}
