rule Win_Trojan_Crypt_245
{
strings:
	$a0 = { e82c000000f30f7e2689e8660f7ee083c60283c6 }


condition:
	$a0
}