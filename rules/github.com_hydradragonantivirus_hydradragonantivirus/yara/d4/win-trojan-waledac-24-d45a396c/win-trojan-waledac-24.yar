rule Win_Trojan_Waledac_24
{
strings:
	$a0 = { c1c10181daf2000000310d00ee4c00b931 }

	$a1 = { bd6c46234b35 }


condition:
	$a0 and $a1
}