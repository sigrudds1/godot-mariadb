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

//TODO(sigrudds1) Change license on pull request
//TODO(sigrudds1) Add sha256 Authentication for MySQL alternative authentication
//TODO(sigrudds1) Add cashing_sha2_password for MySQL alternative authentication
//TODO(sigrudds1) Use virtuallock(windows) or mlock(linux) to prevent memory dump of username and password
//TODO(sigrudds1) ASYNC callbacks using the username, signals maybe.

#ifndef MARIADB_H
#define MARIADB_H

#define DEBUG_OUTPUT

#include <vector>

#include <core/io/ip.h>
#include <core/io/ip_address.h>
#include <core/io/stream_peer_tcp.h>
#include <core/os/thread.h>
#include <core/reference.h>
#include <core/ustring.h>

constexpr int kPacketMaxSize = 0xffffff;
constexpr uint8_t kCharacterCollationId = 33; //utf8_general_ci
constexpr char *kCharacterCollationName = (char *)"utf8_general_ci";

class MariaDB : public Reference {
	GDCLASS(MariaDB, Reference);

public:
	enum AuthSrc {
		AUTH_SRC_UNKNOWN,
		AUTH_SRC_SCRIPT,
		AUTH_SRC_CONSOLE,
		AUTH_SRC_LAST,
	};

	enum AuthType {
		AUTH_TYPE_UNKNOWN,
		AUTH_TYPE_MYSQL_NATIVE,
		AUTH_TYPE_ED25519,
		AUTH_TYPE_LAST,
	};

	enum IpType {
		IP_TYPE_IPV4 = IP::TYPE_IPV4,
		IP_TYPE_IPV6 = IP::TYPE_IPV6,
		IP_TYPE_ANY = IP::TYPE_ANY,
	};

	enum ErrorCodes {
		ERR_NO_ERROR = 0,
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
	enum class Capabilities : uint32_t {
		LONG_PASSWORD = (1UL << 0), //MySQL
		MYSQL = (1UL << 0), //MariaDB - lets server know this is a mysql client
		FOUND_ROWS = (1UL << 1),
		LONG_FLAG = (1UL << 2), //not used in MariaDB
		CONNECT_WITH_DB = (1UL << 3),
		NO_SCHEMA = (1UL << 4), //not used in MariaDB
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
		RESERVED = (1UL << 14), //not used in Maria
		RESERVED2 = (1UL << 15), //Not in Maria Docs but needed
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

	const std::vector<String> kAuthTypeServerNames = { "unknown", "mysql_native_password", "client_ed25519" };
	bool dbl_to_string_ = false;
	IpType ip_type_ = IpType::IP_TYPE_ANY;
	AuthSrc auth_src_ = AUTH_SRC_UNKNOWN;
	AuthType client_auth_type_ = AUTH_TYPE_UNKNOWN;
	bool is_pre_hashed_ = false;
	bool authenticated_ = false;
	uint32_t client_capabilities_ = 0;
	uint32_t client_extended_capabilities_ = 0;
	uint32_t server_capabilities_ = 0;
	uint32_t server_extended_capabilities_ = 0;
	uint32_t error_ = 0;
	bool is_mysql_ = false;
	bool tls_enabled_ = false;

	std::vector<uint8_t> username_;
	std::vector<uint8_t> password_hashed_;
	std::vector<uint8_t> dbname_;

	StreamPeerTCP stream_;
	String server_version_;
	String last_query_;
	PoolByteArray last_query_converted_;
	PoolByteArray last_transmitted_;
	PoolByteArray last_response_;

	/**
	 * \brief			Adds the packet size and sequence number to the beginning of the packet,
	 *					it must be used once just before sending stream to server.
	 * \param stream	std::vector<uint8_t> the stream to be modified.
	 * \param sequance	int
	 */
	void m_add_packet_header(std::vector<uint8_t> &stream, int sequence);
	void m_client_protocol_v41(const AuthType srvr_auth_type, const std::vector<uint8_t> srvr_salt);
	void m_connect(IP_Address ip, int port);

	Variant m_get_gd_type_data(int db_field_type, const char *data);

	String m_get_gdstring_from_buf(std::vector<uint8_t> buf, size_t &start_pos);
	String m_get_gdstring_from_buf(std::vector<uint8_t> buf);

	size_t m_get_packet_length(const std::vector<uint8_t> src_buf, size_t &start_pos);

	/**
	 * \brief			This method returns the defined hash from the combined and scrambled password_hash_ member.
	 *
	 * \param auth_type	enum class AuthType determines what hash is returned from the combined and scrambed hash.
	 * \return			std::vector<uint8_t>.
	 */
	std::vector<uint8_t> m_get_password_hash(const AuthType authtype);

	/**
	 * \brief			This method returns a string from packets using length encoding.
	 *
	 * \param src_buf	const std::vector<uint8_t> packet buffer.
	 * \param last_pos	size_t packet buffer position iterator of the last position used,
	 *					this will be incremented on first use upto byte count.
	 * \param byte_cnt	size_t byte count to be copied from the packet buffer.
	 * \return			std::string.
	 */
	std::string m_get_packet_string(const std::vector<uint8_t> &src_buf, size_t &last_pos, size_t byte_cnt);

	AuthType m_get_server_auth_type(String srvr_auth_name);

	std::vector<uint8_t> m_recv_data(uint32_t timeout);
	//TODO(sigrudds1) Add error log file using the username in the filename
	void m_print_error(std::string error);
	void m_handle_server_error(const std::vector<uint8_t> src_buffer, size_t &last_pos);
	void m_server_init_handshake_v10(const std::vector<uint8_t> &src_buffer);
	void m_update_password(String password);
	void m_update_username(String username);
	PoolByteArray m_vector_byte_to_pool_byte(std::vector<uint8_t> vec);

protected:
	static void _bind_methods();

public:
	uint32_t connect_db(String hostname, int port, String dbname, String username = "", String password = "");
	void disconnect_db();
	String get_last_query();
	PoolByteArray get_last_query_converted();
	PoolByteArray get_last_response();
	PoolByteArray get_last_transmitted();
	bool is_connected_db();

	Variant query(String sql_stmt);

	void update_dbname(String dbname);

	//TODO(sigrudds1) Implement SSL/TLS
	//void tls_enable(bool enable);

	/**
	 * \brief				This method sets the authentication type used.
	 *
	 * \param auth_src		enum AuthSrc determines where the authentication parameters are requested..
	 * \param auth_type		enum AuthType determines what authoriztion type will be statically used.
	 * \param is_pre_hash	bool if set the password used will be hashed by the required type before used.
	 * \return 				uint32_t 0 = no error, see error enum class ErrorCode
	 */
	uint32_t set_authtype(AuthSrc auth_src, AuthType auth_type, bool is_pre_hashed = true);
	void set_dbl2string(bool set_string);
	void set_ip_type(IpType type);
	//TODO(sigrudds1) Async Callbacks

	MariaDB();
	~MariaDB();
};

VARIANT_ENUM_CAST(MariaDB::AuthSrc);
VARIANT_ENUM_CAST(MariaDB::AuthType);
VARIANT_ENUM_CAST(MariaDB::IpType);
VARIANT_ENUM_CAST(MariaDB::ErrorCodes);

#endif
