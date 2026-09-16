rule Win_Trojan_Pebble_1
{
strings:
	$a0 = { b92700ba2c01cd217207e80600b44febf5cd20b8023d }


condition:
	$a0
}