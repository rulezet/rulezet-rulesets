rule Win_Trojan_VGEN_405
{
strings:
	$a0 = { b409cd15b9320051b43cba8a01b92000cd21931e0653b9180281e99701b80000be9701bb0001bfe70ce86102e8 }


condition:
	$a0
}