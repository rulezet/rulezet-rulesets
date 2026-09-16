rule Win_Trojan_Trivial_109
{
strings:
	$a0 = { 4eba1001cd21b43cba9e00cd21cc1b2a2e2a00b74087d193ebf1 }


condition:
	$a0
}