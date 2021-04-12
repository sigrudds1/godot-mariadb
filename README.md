# godot-mariadb
A MariaDB module for the Godot Engine, currently 3.3.0 rc7 but should also work on 4.0.0.  

This module has a self contained connector and does not use the GPL connectors from Maria/MySQL and will compile on Windows and Linux, possiblly Mac.  

Copy to "the-godot-folder"/modules/mariadb/ and run scons, see https://docs.godotengine.org/en/stable/development/compiling/index.html.

-or run-

git clone https://github.com/sigrudds1/godot-mariadb.git "the-godot-folder"/modules/mariadb 

I will have a tutorial up on how to compile and use this module on https://vikingtinkerer.com, once it is stable.  

### Use (gdscipt)  

**Create the object**  
var db = MariaDB.new()  

**Set authorization source and type**  
var auth_ok = db.set_authtype(MariaDB::AuthSrc, MariaDB::AuthType, bool is_pre_hashed). returns int, 0 on success or error code  
**If this method is not used before connect_db(), the password provided will be assumed in plain text and authorization method will be mysql_native_password.**  

#### AuthSrc enum  
Set with MariaDB.AUTH_SRC_...
1. AUTH_SRC_SCRIPT - Uses the username and password parameters in connect_db().
2. AUTH_SRC_CONSOLE - Prompts in the console for username and password in plain text only, password is not echoed.  

#### AuthType enum  
Set with MariaDB.AUTH_TYPE_...
1. AUTH_TYPE_MYSQL_NATIVE - Uses the mysql_native_password login method, this method is default when creating a user in Maria/MySQL, **pre-hash is sha1**.
2. AUTH_TYPE_ED25519 - Uses the, MariaDB only, client_ed25519 authtication plugin, see MariaDb documentation for changing/setting users, **pre-hash is sha512**.

#### is_pre_hashed
If set, the password entered in the connect_db() password parameter should be pre-hashed; use the hashing protocol in enum AuthType description for which type to store. This is particularly useful in autostarting daemons so the password does not need to be stored in plain text, obviously ed25519 sha512 is a more secure method of storing a password. Just keep in mind that anyone who gains access to this stored method, either directly in gdscipt or a file, could still use it to access your DB they just won't know the plain password; limit what the DB user can do or access to minimized and damages that may occur if it was obtained for nefarious purposes. Console password input is the safest of the choices available but not good or easy for autostart.  

**Connect to the database**  
var connect_ok = db.connect_db(String hostname, int port, String db_name, String username, String password). returns int, 0 on success or error code. If AuthSrc::AUTH_SRC_CONSOLE is set then username and password will be ignored and prompted in the console window, you can safely use "" for both parameters in this case.  

**Send query or command**  
var qry = db.query(String sql_stmt) returns Variant, if select statement success return an Array of Dictionaries can be zero length array, other will return int 0 on success or error code.  

**Set IP type**
There are known issues with MariaDB and IPv6 where it doesn't respond to a IPv6 connection attempt. If connecting via localhost the Godot packet_peer_tcp default can be IPv6 for name resolution, you can either connect with 127.0.0.1 or change the IP type to IPv4 if your having problems, some have set the db user host as ::1 (IPv6 loopback) instead of localhost and it works fine.
db.set_ip_type(MariaDB::IpType type) sets the IP type.

#### IpType enum
Set with MariaDB.IP_TYPE_...
1. IP_TYPE_IPV4
2. IP_TYPE_IPV6
3. IP_TYPE_ANY
