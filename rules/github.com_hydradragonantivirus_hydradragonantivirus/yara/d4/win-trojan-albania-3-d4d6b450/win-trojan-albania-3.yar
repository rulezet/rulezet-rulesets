rule Win_Trojan_Albania_3
{
strings:
	$a0 = { 740826807dfe00740541aae80f000e1fba8000b41a }


condition:
	$a0
}