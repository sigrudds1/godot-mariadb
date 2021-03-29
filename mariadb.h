/*************************************************************************/
/*  mariadb.h                                                            */
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

#ifndef MARIADB_H
#define MARIADB_H

#define DEBUG_OUTPUT

#include <vector>
#include <random>

#include <core/crypto/crypto_core.h>
#include <core/reference.h>
#include <core/io/stream_peer_tcp.h>
#include <core/os/thread.h>
#include <core/ustring.h>

constexpr int kPacketMaxSize = 0xffffff;
constexpr uint8_t kCharacterCollationId = 33; //utf8_general_ci
constexpr char *kCharacterCollationName = "utf8_general_ci";

class MariaDB : public Reference {
	GDCLASS(MariaDB, Reference);

	enum class ErrorCodes : uint32_t {
		NO_ERROR = 0,
		SERVER_PROTOCOL_INCOMPATIBLE = (1UL << 0),
		CLIENT_PROTOCOL_INCOMPATIBLE = (1UL << 1),
		AUTH_PLUGIN_REQUIRED = (1UL << 2),
		AUTH_PLUGIN_INCOMPATIBLE = (1UL << 3),
		AUTH_FAILED = (1UL << 4),
	};

	enum class Capabilities : uint32_t {
		LONG_PASSWORD = (unsigned __int64)(1UL << 0), //MySQL
		MYSQL = (1UL << 0), //MariaDB - lets server know this is a mysql client
		FOUND_ROWS = (1UL << 1),
		LONG_FLAG = (1UL << 2), //not used in MariaDB
		CONNECT_WITH_DB = (1UL << 3),
		NO_SCHEMA = (1UL << 4),  //not used in MariaDB
		NO_DB_TABLE_COLUMN = (1UL << 4), //Alternate name, not used in MariaDB
		COMPRESS = (1UL << 5),
		ODBC = (1UL << 6), //not used in Maria
		LOCAL_FILES = (1UL << 7),
		IGNORE_SPACE = (1UL << 8),
		PROTOCOL_41 = (1UL << 9),
		INTERACTIVE = (1UL << 10),
		SSL = (1UL << 11),
		IGNORE_SIGPIPE = (1UL << 12), //mysql
		TRANSACTIONS_MARIA = (1UL << 12), //mariadb
		TRANSACTIONS_MYSQL = (1UL << 13), //MySQL
		SECURE_CONNECTION = (1UL << 13), //mariadb
		RESERVED = (1UL << 14),//not used in Maria
		RESERVED2 = (1UL << 15),//Not in Maria Docs but needed
		MULTI_STATEMENTS = (1UL << 16),
		MULTI_RESULTS = (1UL << 17),
		PS_MULTI_RESULTS = (1UL << 18),
		PLUGIN_AUTH = (1UL << 19),
		CONNECT_ATTRS = (1UL << 20),
		PLUGIN_AUTH_LENENC_CLIENT_DATA = (1UL << 21),
		CAN_HANDLE_EXPIRED_PASSWORDS = (1UL << 22), //not used in Maria
		SESSION_TRACK = (1UL << 23),
		DEPRECATE_EOF = (1UL << 24),
		OPTIONAL_RESULTSET_METADATA = (1UL << 25),
		ZSTD_COMPRESSION_ALGORITHM = (1UL << 26),
		CLIENT_QUERY_ATTRIBUTES = (1UL << 27), //not used in Maria
		//NOT_USED = (1UL << 28),
		CAPABILITY_EXTENSION = (1UL << 29),
		SSL_VERIFY_SERVER_CERT = (1UL << 30), //not used in Maria
		REMEMBER_OPTIONS = (1UL << 31), //not used in Maria

	};

	enum class ExtendedCapabilities : uint32_t {
		MARIADB_CLIENT_PROGRESS = (1UL << 0),
		MARIADB_CLIENT_COM_MULTI = (1UL << 1),
		MARIADB_CLIENT_STMT_BULK_OPERATIONS = (1UL << 2),
		MARIADB_CLIENT_EXTENDED_TYPE_INFO = (1UL << 3),
	};

	struct ColumnData {
		String name;
		uint16_t char_set;
		uint8_t field_type;
	};
	const std::vector<String> kAuthTypeNames = { "unknown", "mysql_native_password", "client_ed25519" }; 

	int pref_auth_type_ = AUTH_TYPE_MYSQL_NATIVE;
	bool async_ = false;
	bool authenticated_ = false;
	uint32_t client_capabilities_ = 0;
	uint32_t client_extended_capabilities_ = 0;
	uint32_t server_capabilities_ = 0;
	uint32_t server_extended_capabilities_ = 0;
	bool connected_ = false;
	uint32_t error_ = 0;
	bool is_mysql_ = false;
	bool tls_enabled_ = false;

	//TODO(sigrud) Use virtuallock(windows) or mlock(linux) to prevent memory dump of seed_, username and password hash
	std::mt19937 Generator;
	size_t seed_ = NULL;

	//TODO(sigrud) remove once pashword hash unscramlbe is implemented
	std::vector<uint8_t> temp_password_sha512_; 

	std::vector<uint8_t> username_;
	std::vector<uint8_t> password_hash_;
	std::vector<uint8_t> dbname_;

	StreamPeerTCP stream_;
	String server_version_;

	/*! \brief	Adds the packet size and sequence number to the beginning of the packet,
	 *			it must be used once just before sending stream to server.
	 */
	void m_add_packet_header(std::vector<uint8_t> &stream, int sequence);
	void m_client_protocol_v41(const int srvr_auth_type, const std::vector<uint8_t> srvr_salt);
	int m_connect(String hostname, int port);

	template <typename T>
	std::vector<T> gdstring_to_vector(String string);
	String m_get_gdstring_from_buf(std::vector<uint8_t> buf, size_t &start_pos);

	//TODO(sigrud) Add sha256 Authentication for MySQL
	//TODO(sigrud) Finish cashing_sha2_password for MySQL alternative authentication
	std::vector<uint8_t> m_get_caching_sha2_password_hash(std::vector<uint8_t> srvr_salt);
	std::vector<uint8_t> m_get_client_ed25519_signature(std::vector<uint8_t> svr_msg);
	std::vector<uint8_t> m_get_mysql_native_password_hash(std::vector<uint8_t> srvr_salt);
	size_t m_get_packet_length(const std::vector<uint8_t> src_buf, size_t &start_pos);

	/**
	 * \brief			This method returns a string from packets using length encoding.
	 *
	 * \param src_buf	const std::vector<uint8_t> packet buffer.
	 * \param last_pos	size_t packet buffer position iterator of the last position used,
	 *					this will be incremented on first use upto byte count.
	 * \param byte_cnt	size_t byte count to be copied from the packet buffer.
	 * \return			std::string.
	 */
	std::string m_get_packet_string(const std::vector<uint8_t> src_buf, size_t &last_pos, size_t byte_cnt);

	int m_get_server_auth_type(String srvr_auth_name);

	std::vector<uint8_t> m_recv_data(uint32_t timeout);
	//TODO(sigrud) Add error log file using the username in the filename
	void m_print_error(std::string error);
	void m_print_server_error(const std::vector<uint8_t> src_buffer, size_t &last_pos);
	void m_server_init_handshake_v10(const std::vector<uint8_t> src_buffer);
	void m_set_seed(size_t seed = NULL);
	void m_update_password(String password);
	void m_update_username(String username);

protected:
	static void _bind_methods();

public:
	enum AuthType {
		AUTH_TYPE_UNKNOWN,
		AUTH_TYPE_MYSQL_NATIVE, //default
		AUTH_TYPE_ED25519,
	};

	//blocking members
	int connect_db(String hostname, String username, String password, int port, String dbname);
	void disconnect_db();

	//int execute(String command);
	
	//TODO(sigrud) ASYNC callback using the username, signal maybe?
	Variant query(String sql_stmt);

	void update_dbname(String dbname);

	//TODO(sigrud) Implement SSL/TLS
	//void tls_enable(bool enable);

	void set_authtype(AuthType auth_type, String password);

	//async members
	//void connect_db_async(String host, String user, String pass, int port);

	MariaDB();
	~MariaDB();
};

VARIANT_ENUM_CAST(MariaDB::AuthType);
#endif
