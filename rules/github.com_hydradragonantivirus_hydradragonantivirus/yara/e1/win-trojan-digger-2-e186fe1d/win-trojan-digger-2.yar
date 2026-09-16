rule Win_Trojan_Digger_2
{
strings:
	$a0 = { e404bb040051b1042ed2015943e2f65b3d9b1b7408e9a8 }


condition:
	$a0
}