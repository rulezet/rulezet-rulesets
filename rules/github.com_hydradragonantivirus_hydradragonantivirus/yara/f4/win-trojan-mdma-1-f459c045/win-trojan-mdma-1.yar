rule Win_Trojan_MDMA_1
{
strings:
	$a0 = { 010100550001000000ffff18030000e802000003000000e014 }


condition:
	$a0
}