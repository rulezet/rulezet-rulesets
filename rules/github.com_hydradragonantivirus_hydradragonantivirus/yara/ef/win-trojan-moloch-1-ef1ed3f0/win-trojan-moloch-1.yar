rule Win_Trojan_Moloch_1
{
strings:
	$a0 = { 8ed0bc007c1607b90f4fb300ba0001b003b402b77ccd13 }


condition:
	$a0
}