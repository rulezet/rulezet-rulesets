rule Win_Trojan_Peed_412
{
strings:
	$a0 = { e8110000008b150000fe7f81fa000003007f12f8abc3b80000f07f }


condition:
	$a0
}