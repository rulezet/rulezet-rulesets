rule Win_Trojan_Trivial_53
{
strings:
	$a0 = { 8bd483c220cd218bd8b440ba0001b97100cd21b43ecd21 }


condition:
	$a0
}