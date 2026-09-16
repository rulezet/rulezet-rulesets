rule Win_Trojan_PC_4
{
strings:
	$a0 = { f6a2b90500b43fe87f00b4bb3a26f6a2 }


condition:
	$a0
}