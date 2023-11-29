extends Node

# See the create_db.sql file to insall the data needed for this test
# Run the insert record functions once, then comment it out.

var ed:Dictionary = {
	"db_plain_text_pwd": "secret",
	"db_sha512_hashed_pwd": "bd2b1aaf7ef4f09be9f52ce2d8d599674d81aa9d6a4421696dc4d93dd0619d682ce56b4d64a9ef097761ced99e0f67265b5f76085e5b0ee7ca4696b2ad6fe2b2",
	"db_hostname": "127.0.0.1",
	"db_max_conns": 5,
	"db_name": "Godot_Test",
	"db_port": 3306,
	"db_user": "godot_user"
}

var qry_stmt_array: PackedStringArray = [
	"SELECT * FROM Godot_Test.many_records;",
	"SELECT * FROM Godot_Test.many_columns;"
]

var query_tmr: float = 0
var itr: int = 0
var db: MariaDB

func _ready() -> void:
	db = MariaDB.new()
	_connect_to_db_srvr()
#	_insert_many_columns()
#	_insert_many_records()
	%Timer.start()
#	_run_db()

func _exit_tree() -> void:
	db.disconnect_db()


func print_db_response(pba: PackedByteArray) -> void:
	for idx in range(pba.size() - 1, -1, -1):
		if pba[idx] < 32:
			pba.remove_at(idx)
	print(pba.get_string_from_ascii())


func _run_db() -> void:
	if !db.is_connected_db():
		_connect_to_db_srvr()
	else:
		var start_uticks := Time.get_ticks_usec()
		var stmt: String = qry_stmt_array[itr % qry_stmt_array.size()]
#		var stmt: String = qry_stmt_array[0]
#		print(stmt)
		var qry = db.query(stmt)
		if typeof(qry) == TYPE_ARRAY:
#			if qry.size() > 0:
#				if qry[0].has("text_field"):
#					for i in qry.size():
#						if qry[i]["text_field"] != null:
#							var string: String = str(qry[i]["text_field"])
#							var strlen: int = string.length()
#							if strlen >= 20:
#								print(qry[i]["text_field"].left(10), qry[i]["text_field"].right(10))
#							else:
#								print(string.left(strlen >> 1), string.right(strlen >> 1))
#
#				print("column count:", qry[0].size())
		#	print("\n", db.get_last_response())
#			var end_uticks := Time.get_ticks_usec()
			print("total records received:", qry.size(), " time:", Time.get_ticks_usec() - start_uticks, " usecs itr:", itr)
		else:
			%Timer.stop()
			print(itr)
#			print(stmt)
			print("itr:", itr, " - ERROR:", qry)
		
		itr += 1


func _connect_to_db_srvr() -> void:
	var err = db.connect_db(
			ed["db_hostname"],
			ed["db_port"],
			ed["db_name"],
			ed["db_user"],
			ed["db_sha512_hashed_pwd"],
			MariaDB.AUTH_TYPE_ED25519,
			true
		);
	if err:
		print("db connect err:", err)


func _insert_many_columns() -> void:
	var stmt: String = "INSERT INTO Godot_Test.many_columns VALUES "
	for i in range(1, 253):
		stmt += "(%d)" % i
	
	print(stmt)
	var err = db.query(stmt)
	if err != OK:
		printerr("Insert fail:" , err)


func _insert_many_records() -> void:
	var stmt: String = "INSERT INTO Godot_Test.`many_records (type, zone_id, player_id, map_id, " +\
			"text_field VALUES " 
	for i in 10:
		stmt += "(%d, %d, %d, %d, %s)" % [i * 10 + 1, i * 10 + 2, i * 10 + 3, i * 10 + 4, "Some text for record %d" % i]
	
	print(stmt)
	var err = db.query(stmt)
	if err != OK:
		printerr("Insert fail:" , err)


func _on_timer_timeout() -> void:
	_run_db()
