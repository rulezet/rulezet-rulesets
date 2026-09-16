rule Win_Trojan_Tiny_90
{
strings:
	$a0 = { 010100558e010000000100000000001f000000040000004503 }


condition:
	$a0
}