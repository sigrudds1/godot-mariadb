/*************************************************************************/
/*  mariadb.h                                                            */
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

//TODO(sigrudds1) Add sha256 Authentication for MySQL alternative authentication
//TODO(sigrudds1) Add cashing_sha2_password for MySQL alternative authentication
//TODO(sigrudds1) Use virtuallock(windows) or mlock(linux) to prevent memory dump of username and password
//TODO(sigrudds1) ASYNC callbacks using the username, signals maybe.

#ifndef MARIADB_H
#define MARIADB_H

#define DEBUG_OUTPUT

#include <core/io/ip.h>
#include <core/io/ip_address.h>
#include <core/io/stream_peer_tcp.h>
// #include "core/os/thread.h"
// #include "core/os/mutex.h"
#include "core/object/ref_counted.h"
#include "core/string/ustring.h"
#include "core/templates/vector.h"
#include "core/variant/variant.h"


constexpr uint8_t kCharacterCollationId = 33; //utf8_general_ci
constexpr char *kCharacterCollationName = (char *)"utf8_general_ci";

class MariaDB : public RefCounted {
	GDCLASS(MariaDB, RefCounted);

public:
	enum AuthType {
		AUTH_TYPE_ED25519,
		AUTH_TYPE_MYSQL_NATIVE,
		AUTH_TYPE_LAST,
	};

	enum IpType {
		IP_TYPE_IPV4 = IP::TYPE_IPV4,
		IP_TYPE_IPV6 = IP::TYPE_IPV6,
		IP_TYPE_ANY = IP::TYPE_ANY,
	};

	enum ErrorCodes {
		OK = 0,
		ERR_NO_RESPONSE,
		ERR_NOT_CONNECTED,
		ERR_PACKET_LENGTH_MISMATCH,
		ERR_PACKET_SEQUENCE_ERROR,
		ERR_SERVER_PROTOCOL_INCOMPATIBLE,
		ERR_CLIENT_PROTOCOL_INCOMPATIBLE,
		ERR_AUTH_PLUGIN_NOT_SET,
		ERR_AUTH_PLUGIN_INCOMPATIBLE,
		ERR_AUTH_FAILED,
		ERR_USERNAME_EMPTY,
		ERR_PASSWORD_EMPTY,
		ERR_DB_EMPTY
	};

private:
	//https://mariadb.com/kb/en/connection/#capabilities
	enum class Capabilities : uint64_t {
		LONG_PASSWORD = (1UL << 0), //MySQL
		CLIENT_MYSQL = (1UL << 0), //MariaDB - lets server know this is a mysql client
		FOUND_ROWS = (1UL << 1),
		LONG_FLAG = (1UL << 2), //Not listed in MariaDB
		CONNECT_WITH_DB = (1UL << 3),
		NO_SCHEMA = (1UL << 4), //Not listed in MariaDB
		NO_DB_TABLE_COLUMN = (1UL << 4), //Alternate name, Not listed in MariaDB
		COMPRESS = (1UL << 5),
		ODBC = (1UL << 6), //Not listed in MariaDB
		LOCAL_FILES = (1UL << 7),
		IGNORE_SPACE = (1UL << 8),
		CLIENT_PROTOCOL_41 = (1UL << 9),
		CLIENT_INTERACTIVE = (1UL << 10),
		SSL = (1UL << 11),
		IGNORE_SIGPIPE = (1UL << 12), //MySQL
		TRANSACTIONS_MARIA = (1UL << 12), //MariaDB
		TRANSACTIONS_MYSQL = (1UL << 13), //MySQL
		SECURE_CONNECTION = (1UL << 13), //MariaDB
		RESERVED = (1UL << 14), //Not listed in MariaDB
		RESERVED2 = (1UL << 15), //Not in Maria Docs but needed
		MULTI_STATEMENTS = (1UL << 16),
		MULTI_RESULTS = (1UL << 17),
		PS_MULTI_RESULTS = (1UL << 18),
		PLUGIN_AUTH = (1UL << 19),
		CLIENT_SEND_CONNECT_ATTRS = (1UL << 20),
		PLUGIN_AUTH_LENENC_CLIENT_DATA = (1UL << 21), //TODO Add compatibility
		CAN_HANDLE_EXPIRED_PASSWORDS = (1UL << 22), //Not listed in MariaDB
		SESSION_TRACK = (1UL << 23),
		CLIENT_DEPRECATE_EOF = (1UL << 24),
		OPTIONAL_RESULTSET_METADATA = (1UL << 25),
		CLIENT_ZSTD_COMPRESSION_ALGORITHM = (1UL << 26),
		CLIENT_QUERY_ATTRIBUTES = (1UL << 27), //Not listed in MariaDB
		//NOT_USED = (1UL << 28),
		CLIENT_CAPABILITY_EXTENSION = (1UL << 29), //MariaDB reserved for future use.
		SSL_VERIFY_SERVER_CERT = (1UL << 30), //Not listed in MariaDB
		REMEMBER_OPTIONS = (1UL << 31), //Not listed in MariaDB
		MARIADB_CLIENT_PROGRESS = (1UL << 32),
		MARIADB_CLIENT_COM_MULTI = (1UL << 33),
		MARIADB_CLIENT_STMT_BULK_OPERATIONS = (1UL << 34),
		MARIADB_CLIENT_EXTENDED_TYPE_INFO = (1UL << 35),
		MARIADB_CLIENT_CACHE_METADATA = (1UL << 36)
	};

	struct ColumnData {
		String name;
		uint16_t char_set;
		uint8_t field_type;
	};

	const Vector<String> kAuthTypeNames = { "client_ed25519", "mysql_native_password"  };
	bool _dbl_to_string = false;
	IpType _ip_type = IpType::IP_TYPE_ANY;
	AuthType _client_auth_type = AUTH_TYPE_ED25519;
	bool _is_pre_hashed = true;
	bool _authenticated = false;
	uint64_t _client_capabilities = 0;
	//uint32_t _client_extended_capabilities = 0;
	uint64_t _server_capabilities = 0;
	//uint32_t _server_extended_capabilities = 0;

	Vector<uint8_t> _username;
	Vector<uint8_t> _password_hashed;
	Vector<uint8_t> _dbname;

	// Ref<StreamPeerTCP> tcp_connection;

	StreamPeerTCP _stream;
	IPAddress _ip;
	int _port = 0;

	// bool _running = true;
	// bool _tcp_polling = false;
	// Mutex _tcp_mutex;
	// Thread _tcp_thread;
	// Vector<uint8_t> _tcp_thread_data;

	String _protocol_ver;
	String _server_ver_str;
	uint8_t _srvr_major_ver = 0;
	uint8_t _srvr_minor_ver = 0;
	String _last_query;
	Vector<uint8_t> _last_query_converted;
	Vector<uint8_t> _last_transmitted;
	Vector<uint8_t> _last_response;


	/**
	 * \brief			Adds the packet size and sequence number to the beginning of the packet,
	 *					it must be used once just before sending stream to server.
	 * \param stream	std::vector<uint8_t> the stream to be modified.
	 * \param sequance	int
	 */
	void m_add_packet_header(Vector<uint8_t> &p_pkt, uint8_t p_pkt_seq);

	// void m_append_thread_data(PackedByteArray &p_data, const uint64_t p_timeout = 1000);

	uint32_t m_chk_rcv_bfr(Vector<uint8_t> &bfr, int &bfr_size, const size_t cur_pos, const size_t need);

	Error m_client_protocol_v41(const AuthType p_srvr_auth_type, const Vector<uint8_t> p_srvr_salt);
	Error m_connect();
	static void m_tcp_thread_func(void *instance);

	String m_find_vbytes_str_at(Vector<uint8_t> p_buf, size_t &p_start_pos);
	String m_find_vbytes_str(Vector<uint8_t> p_buf);

	PackedByteArray m_get_pkt_bytes(const Vector<uint8_t> &src_buf, size_t &start_pos, const size_t byte_cnt);
	size_t m_get_pkt_len_at(const Vector<uint8_t> p_src_buf, size_t &p_start_pos);
	AuthType m_get_server_auth_type(String p_srvr_auth_name);
	Variant m_get_type_data(const int p_db_field_type, const PackedByteArray p_data);

	Vector<uint8_t> m_recv_data();
	Vector<uint8_t> m_recv_data(uint32_t p_timeout);
	//TODO(sigrudds1) Add error log file using the username in the filename
	void m_handle_server_error(const Vector<uint8_t> p_src_buffer, size_t &p_last_pos);
	Error m_server_init_handshake_v10(const Vector<uint8_t> &p_src_buffer);
	void m_update_password(String p_password);
	void m_update_username(String P_username);

protected:
	static void _bind_methods();

public:
	/**
	 * \brief				This method sets the authentication type used.
	 *
	 * \param host
	 * \param port
	 * \param dbname
	 * \param username
	 * \param password
	 * \param auth_type		enum AuthType determines what authoriztion type will be statically used.
	 * \param is_pre_hash	bool if set the password used will be hashed by the required type before used.
	 * \return 				uint32_t 0 = no error, see error enum class ErrorCode
	 */
	Error connect_db(String host, int port, String dbname, String username, String password,
			AuthType auth_type = AuthType::AUTH_TYPE_ED25519, bool is_prehashed = true);
	void disconnect_db();

	String get_last_query();
	PackedByteArray get_last_query_converted();
	PackedByteArray get_last_response();
	PackedByteArray get_last_transmitted();

	bool is_connected_db();

	Variant query(String sql_stmt);


	//TODO(sigrudds1) Implement SSL/TLS
	//void tls_enable(bool enable);

	void set_dbl_to_string(bool is_to_str);
	void set_db_name(String p_db_name);
	void set_ip_type(IpType p_type);
	//TODO(sigrudds1) Async Callbacks

	MariaDB();
	~MariaDB();
};

VARIANT_ENUM_CAST(MariaDB::AuthType);
VARIANT_ENUM_CAST(MariaDB::IpType);

#endif
