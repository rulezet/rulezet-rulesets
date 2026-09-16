rule Win_Trojan_Doggie_3
{
strings:
	$a0 = { 020055df00000200ffff010300004e010000030000001003 }


condition:
	$a0
}