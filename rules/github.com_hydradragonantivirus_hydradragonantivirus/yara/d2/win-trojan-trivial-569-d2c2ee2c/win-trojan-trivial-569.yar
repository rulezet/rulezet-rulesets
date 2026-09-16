rule Win_Trojan_Trivial_569
{
strings:
	$a0 = { 8bfeb18fac34??aafec980f9ff75 }


condition:
	$a0
}