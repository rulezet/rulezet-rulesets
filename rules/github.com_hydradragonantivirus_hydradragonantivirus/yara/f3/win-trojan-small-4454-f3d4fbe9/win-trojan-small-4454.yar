rule Win_Trojan_Small_4454
{
strings:
	$a0 = { 8d05??858503683255430350e84600000050 }


condition:
	$a0
}