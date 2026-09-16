rule Win_Trojan_Karnos_1
{
strings:
	$a0 = { 476c6f62616c5c323031326d6f6e5f7765625f6b6579776f7264 }


condition:
	$a0
}