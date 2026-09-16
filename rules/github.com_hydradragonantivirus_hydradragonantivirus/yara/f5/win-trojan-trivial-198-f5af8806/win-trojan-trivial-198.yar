rule Win_Trojan_Trivial_198
{
strings:
	$a0 = { 2001b44ecd21ba9e00b8023dcd21938ad0b442cd21b440b125b601cd21c3 }


condition:
	$a0
}