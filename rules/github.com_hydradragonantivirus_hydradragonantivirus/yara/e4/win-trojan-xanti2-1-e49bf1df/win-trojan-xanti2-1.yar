rule Win_Trojan_Xanti2_1
{
strings:
	$a0 = { c686ce0206b41a8d96a302cd21b82435cd21899e9f028c86 }


condition:
	$a0
}