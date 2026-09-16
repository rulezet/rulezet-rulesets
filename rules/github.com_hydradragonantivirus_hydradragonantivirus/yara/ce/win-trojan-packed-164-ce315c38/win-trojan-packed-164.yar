rule Win_Trojan_Packed_164
{
strings:
	$a0 = { 5783ec7c545f680001000057e8????00006a005703f8b85c6d7072abb86d73672eabb8646c6c00ab33c0abe8????0000 }


condition:
	$a0
}