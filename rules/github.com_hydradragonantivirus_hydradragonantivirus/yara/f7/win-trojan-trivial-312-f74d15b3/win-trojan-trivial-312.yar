rule Win_Trojan_Trivial_312
{
strings:
	$a0 = { ebe02e2e00b43b5aba2801cd2173cbc3 }


condition:
	$a0
}