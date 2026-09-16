rule Win_Trojan_Amt_2
{
strings:
	$a0 = { 3f4d5a740ce801032bc05e5f8be55dc390e82703b104c4 }


condition:
	$a0
}