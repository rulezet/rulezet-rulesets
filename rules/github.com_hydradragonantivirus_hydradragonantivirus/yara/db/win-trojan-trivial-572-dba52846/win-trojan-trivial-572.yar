rule Win_Trojan_Trivial_572
{
strings:
	$a0 = { b8023dba????cd2193b440ba0001b1??cd21b43ecd21b44fcd21 }


condition:
	$a0
}