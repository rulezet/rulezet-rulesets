rule Win_Trojan_Pox_5
{
strings:
	$a0 = { 0190e86503e800005d81ed090150535152565755061eb8cdabcd2181fbcdab747d0e1f8cc1b80935cd212e8c860702 }


condition:
	$a0
}