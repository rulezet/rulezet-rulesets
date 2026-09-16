rule Win_Trojan_Small_4372
{
strings:
	$a0 = { b808010070[0-255]8d5c20008d7c23008d742300b9a0080000 }


condition:
	$a0
}