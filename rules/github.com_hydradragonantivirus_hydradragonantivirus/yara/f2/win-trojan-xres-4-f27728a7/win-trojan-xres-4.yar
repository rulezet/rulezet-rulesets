rule Win_Trojan_XRes_4
{
strings:
	$a0 = { 5e83ee03061eb420cd210ac07567b448bb2200cd2173128cd8488ed88b1e030083eb23b44acd21ebe5488ec04026c7 }


condition:
	$a0
}