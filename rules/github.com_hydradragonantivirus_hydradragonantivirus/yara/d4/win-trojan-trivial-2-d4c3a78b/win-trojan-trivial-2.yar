rule Win_Trojan_Trivial_2
{
strings:
	$a0 = { 35003c4187f2cd2193b440cd21 }


condition:
	$a0
}