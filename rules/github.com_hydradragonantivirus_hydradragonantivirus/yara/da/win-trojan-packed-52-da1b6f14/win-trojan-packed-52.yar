rule Win_Trojan_Packed_52
{
strings:
	$a0 = { e925e4ffff000000 }

	$a1 = { 43e5e2e2e2da176855081752443030411a6d586e4a6f8587885a2a2424262d2d }


condition:
	$a0 and $a1
}