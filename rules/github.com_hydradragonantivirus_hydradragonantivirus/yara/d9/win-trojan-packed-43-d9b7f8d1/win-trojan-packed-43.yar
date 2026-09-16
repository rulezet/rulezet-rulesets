rule Win_Trojan_Packed_43
{
strings:
	$a0 = { 5800e8[0-250]e883ed048945 }


condition:
	$a0
}