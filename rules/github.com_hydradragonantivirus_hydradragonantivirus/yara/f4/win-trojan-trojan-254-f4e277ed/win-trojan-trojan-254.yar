rule Win_Trojan_Trojan_254
{
strings:
	$a0 = { 5d8bf556b00fb9a302482e300446e2f9c3 }


condition:
	$a0
}