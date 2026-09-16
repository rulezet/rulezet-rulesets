rule Win_Trojan_VGEN_608
{
strings:
	$a0 = { b409cd21b9320051ba4f010e1f33c9b43ccd2150ba8301b92500bb000116580500108ec0e886005bb440cd21b4 }


condition:
	$a0
}