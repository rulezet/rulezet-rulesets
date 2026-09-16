rule Win_Trojan_BlackPOS_3
{
strings:
	$a0 = { 7a3a5c536c656e6465725c6d6f7a6172745c6d6f7a6172745c52656c656173655c6d6f7a6172742e706462 }


condition:
	$a0
}