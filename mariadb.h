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
		CLIENT_PROTOCOL_41 = (1UL << 9),
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
		CLIENT_DEPRECATE_EOF = (1UL << 24),
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

	const Vector<String> kAuthTypeServerNames = String("unknown,mysql_native_password,client_ed25519").split(",");
	bool dbl_to_string_ = false;
	IpType ip_type_ = IpType::IP_TYPE_ANY;
	AuthType _client_auth_type  = AUTH_TYPE_ED25519;
	bool _is_pre_hashed = false;
	bool _authenticated = false;
	uint32_t _client_capabilities = 0;
	uint32_t client_extended_capabilities_ = 0;
	uint32_t _server_capabilities = 0;
	uint32_t server_extended_capabilities_ = 0;
	uint32_t error_ = 0;
	bool is_mysql_ = false;
	bool tls_enabled_ = false;

	Vector<uint8_t> _username;
	Vector<uint8_t> _password_hashed;
	Vector<uint8_t> _dbname;

	StreamPeerTCP _stream;
	String _server_ver;
	String _last_query;
	
	Vector<uint8_t> _last_transmitted;
	Vector<uint8_t> _last_response;

	/**
	 * \brief			Adds the packet size and sequence number to the beginning of the packet,
	 *					it must be used once just before sending stream to server.
	 * \param stream	Vector<uint8_t> the stream to be modified.
	 * \param sequance	int
	 */
	void m_add_packet_header(Vector<uint8_t> &p_pkt, uint8_t p_pkt_seq);
	void m_client_protocol_v41(const AuthType srvr_auth_type, const Vector<uint8_t> srvr_salt);
	void m_connect(IP_Address ip, int port);
	int m_dec_3byte_pkt_len_at(const Vector<uint8_t> p_src_buf, int &p_start_pos);

	Variant m_get_gd_type_data(const int db_field_type, const String data);

	String m_get_gdstring_from_buf(Vector<uint8_t> buf, int &start_pos);
	String m_get_gdstring_from_buf(Vector<uint8_t> buf);

	int m_get_packet_length(const Vector<uint8_t> src_buf, int &start_pos);

	/**
	 * \brief			This method returns the defined hash from the combined and scrambled password_hash_ member.
	 *
	 * \param auth_type	enum class AuthType determines what hash is returned from the combined and scrambed hash.
	 * \return			Vector<uint8_t>.
	 */
	Vector<uint8_t> m_get_password_hash(const AuthType authtype);

	/**
	 * \brief			This method returns a string from packets using length encoding.
	 *
	 * \param src_buf	const Vector<uint8_t> packet buffer.
	 * \param last_pos	int packet buffer position iterator of the last position used,
	 *					this will be incremented on first use upto byte count.
	 * \param byte_cnt	int byte count to be copied from the packet buffer.
	 * \return			std::string.
	 */
	String m_get_packet_string(const Vector<uint8_t> &src_buf, int &last_pos, const int byte_cnt);

	AuthType m_get_server_auth_type(String srvr_auth_name);

	Vector<uint8_t> m_recv_data(int timeout);
	//TODO(sigrudds1) Add error log file using the username in the filename
	void m_handle_server_error(const Vector<uint8_t> src_buffer, int &last_pos);
	void m_server_init_handshake_v10(const Vector<uint8_t> &p_src_buffer);
	void m_update_password(String password);

protected:
	static void _bind_methods();

public:
	int connect_db(String p_hostname, int p_port, String p_dbname, String p_username, String p_password);
	void disconnect_db();
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
	int set_authtype(AuthType auth_type, bool is_pre_hashed);
	void set_dbl2string(bool set_string);
	void set_ip_type(IpType type);
	//TODO(sigrudds1) Async Callbacks

	MariaDB();
	~MariaDB();
};

VARIANT_ENUM_CAST(MariaDB::AuthType);
VARIANT_ENUM_CAST(MariaDB::IpType);
VARIANT_ENUM_CAST(MariaDB::ErrorCodes);

#endif
