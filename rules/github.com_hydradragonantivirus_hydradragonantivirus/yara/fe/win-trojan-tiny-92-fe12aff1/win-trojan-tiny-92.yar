rule Win_Trojan_Tiny_92
{
strings:
	$a0 = { 01010055a6000000000100000000002a000000030000004503 }


condition:
	$a0
}