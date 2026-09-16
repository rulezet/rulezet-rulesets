rule Win_Trojan_Justice_4
{
strings:
	$a0 = { da049c0ee870fc723881fedddd750a2ec7063d000155eb0f }


condition:
	$a0
}