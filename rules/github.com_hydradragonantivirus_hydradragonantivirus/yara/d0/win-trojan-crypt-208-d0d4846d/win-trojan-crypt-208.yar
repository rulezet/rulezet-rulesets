rule Win_Trojan_Crypt_208
{
strings:
	$a0 = { f87309261cada03c3ca9ae2d6052ba0460302881ea0a12f301011424 }

	$a1 = { bf707369417253654e00414242 }


condition:
	$a0 and $a1
}