# godot-mariadb
A MariaDB module for the Godot Engine, created on 3.4 and currently works on 3.5.1 but should also work on any 3.x, checkout the 4.0 branch for Godot 4.x.  

This module has a self contained connector and does not use the GPL connectors from Maria/MySQL and will compile on Windows, Linux, probably Mac.  

**To compile on to a stable version you will need to clone the Godot repo...**  
git clone https://github.com/godotengine/godot.git  

**List the stable releases with...**  
git tag -l  
**-or- find a major release with...**  
git tag -l '3.5\*stable*'  

**Checkout the stable release you want...**  
git checkout 3.5.2-stable  

**Change to the modules directory...**  
cd modules  

**Clone this repo as a git submodule...**  
git submodule add https://github.com/sigrudds1/godot-mariadb.git mariadb  

**Change to the just created mariadb directory...**  
cd mariadb  

**Find the relevant release to the Godot version...**  
git tag  

**Checkout/switch to the relevant release, e.g. match Godot 3.5.1-stable, requires git version 2.23+**  
git checkout v3.5.1  
  
 **Alternately you can use a branch rather than release...**  
git branch -v -a  

**Checkout the branch, e.g. 3.x, git version 2.23+**  
git checkout 3.x  
  
**Change back to the main Godot directory...**  
cd ../..  

**Compile Godot, e.g. editor version for Linux 64 bit, see the Godot manual for other releases and export templates, make sure you're on the correct manual version.**  
[Godot 3.5.x Linux](https://docs.godotengine.org/en/3.5/development/compiling/compiling_for_x11.html)  
scons -j$(nproc) platform=x11  

I will have a tutorial up on https://vikingtinkerer.com, once I feel it has been tested enough to be considered stable.  
  
[Buy Me A Coffee](https://buymeacoffee.com/VikingTinkerer)  
  or  
[Buy Me A Ko-Fi](https://ko-fi.com/vikingtinkerer)  
  
### Use (gdscipt)  

**Create the object**  
var db := MariaDB.new()  

**Set authorization source and type**  
var auth_ok : int = db.set_authtype(MariaDB::AuthSrc, MariaDB::AuthType, bool is_pre_hashed). returns int, 0 on success or error code  
**If this method is not used before connect_db(), the password provided will be assumed in plain text and authorization method will be mysql_native_password.**  

#### AuthSrc enum (3.x only)  
Set with MariaDB.AUTH_SRC_...  
1. AUTH_SRC_SCRIPT - Uses the username and password parameters in connect_db().
2. AUTH_SRC_CONSOLE - Prompts in the console for username and password in plain text only, password is not echoed.  

#### AuthType enum  
Set with MariaDB.AUTH_TYPE_...  
1. AUTH_TYPE_MYSQL_NATIVE - Uses the mysql_native_password login method, this method is default when creating a user in Maria/MySQL, **pre-hash is sha1**.  
2. AUTH_TYPE_ED25519 - Uses the, MariaDB only, client_ed25519 authtication plugin, see MariaDB documentation for changing/setting users, **pre-hash is sha512**.  

#### is_pre_hashed  
If set, the password entered in the connect_db() password parameter should be pre-hashed; use the hashing protocol in enum AuthType description for which type to store. This is particularly useful in autostarting daemons so the password does not need to be stored in plain text, obviously ed25519 sha512 is a more secure method of storing a password. Just keep in mind that anyone who gains access to this stored method, either directly in gdscipt or a file, could still use it to access your DB they just won't know the plain password; limit what the DB user can do or access to minimized and damages that may occur if it was obtained for nefarious purposes. Console password input is the safest of the choices available but not good or easy for autostart. Never store the DB password even in hashed form anywhere the client can gain access, Godot engine encryption is not good enough and the password will be found by hackers. This module is intended for server side only.   

**Connect to the database**  
var connect_ok : int = db.connect_db(String hostname, int port, String db_name, String username, String password).  
Returns int, 0 on success or error code. If AuthSrc::AUTH_SRC_CONSOLE is set then username and password will be ignored and prompted in the console window, you can safely use "" for both parameters in this case.  

**Check connection**  
var db_connected : bool = db.is_connected_db()  

**Send query or command**  
var qry = db.query(String sql_stmt)  
Returns Variant, if select statement success return an Array of Dictionaries can be zero length array, other will return int 0 on success or error code. The value can be tested for NULL with typeof(dictionary.keyname) and the return will be 0 or TYPE_NIL, the text output will be keyname:Null with print(). Errors will also be output to the console with full description of the error from the DB server.  

**Set DOUBLE as String**  
db.set_dbl2string(true|false) default false  
Set the return type of a Double column type to String to peel off the digits past the decimal to try and preserve precision.  
  
**Set IP type**  
db.set_ip_type(MariaDB::IpType type)  
Sets the IP type.  
There are known issues with MariaDB and IPv6 where it doesn't respond to localhost. If connecting using localhost the Godot stream_peer_tcp default can be IPv6 for name resolution resulting in ::1, you can either connect with 127.0.0.1 instead of localhost or change the IP type to IPv4 if the db users host column is set to localhost and you are having problems, you can also set or add another db user entry host as ::1 (IPv6 loopback) instead of localhost and it works fine, you will need to comment out the db bind_address configuration for multiple ipv4 and ipv6 localhost entries.  

#### IpType enum  
Set with MariaDB.IP_TYPE_...  
1. IP_TYPE_IPV4  
2. IP_TYPE_IPV6  
3. IP_TYPE_ANY

**Get the last query statement**  
var last_qry : String = db.get_last_query()  
Returns the String used in the query, this was implemented to troublehsoot characterset issues.  
  
**Get the last query statement converted to uint8_t**  
var pba : PoolByteArray = db.get_last_query_converted()    
Returns the vector<uint8_t> as PoolByteArray used in the query just before transmitting to the server, this was implemented to troublehsoot characterset issues.  

**Get the stream send to the DB server**  
var pba : PoolByteArray = db.get_last_transmitted()  
Returns the vector<uint8_t> send to the server, this includes the protocol header.  
  
**Get the stream received from the DB server response**  
var pba : PoolByteArray = db.get_last_response()  
Returns the vector<uint8_t> recieved from the server.  
