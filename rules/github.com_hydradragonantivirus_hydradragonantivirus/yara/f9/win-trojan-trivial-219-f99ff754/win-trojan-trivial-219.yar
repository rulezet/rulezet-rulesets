rule Win_Trojan_Trivial_219
{
strings:
	$a0 = { ba2001b92400cd21ba9e00b8023dcd219392fec6b440cd21b43ecd21cd20 }


condition:
	$a0
}