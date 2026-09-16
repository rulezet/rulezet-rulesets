rule Win_Trojan_Agent_35415
{
strings:
	$a0 = { 608d5424408b2abe000000005558c1e81881f87c00000074118d44242c8b28be253b }


condition:
	$a0
}