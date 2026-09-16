rule Win_Trojan_Packed_167
{
strings:
	$a0 = { 5783ec7c545f6a7c57e8????00006a005703f8b85c6d6369abb877617665abb82e646c6cab33 }


condition:
	$a0
}