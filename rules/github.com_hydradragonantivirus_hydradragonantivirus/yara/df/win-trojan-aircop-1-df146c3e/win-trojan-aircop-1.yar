rule Win_Trojan_Aircop_1
{
strings:
	$a0 = { 32e4cd16cd1233c0cd130e07b80002b9 }


condition:
	$a0
}