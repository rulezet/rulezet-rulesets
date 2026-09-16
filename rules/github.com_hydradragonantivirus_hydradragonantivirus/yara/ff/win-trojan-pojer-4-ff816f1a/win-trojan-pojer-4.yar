rule Win_Trojan_Pojer_4
{
strings:
	$a0 = { 5ef883ee09bb240003def82e8a944707f8b9f0062e3017f843e2f9 }


condition:
	$a0
}