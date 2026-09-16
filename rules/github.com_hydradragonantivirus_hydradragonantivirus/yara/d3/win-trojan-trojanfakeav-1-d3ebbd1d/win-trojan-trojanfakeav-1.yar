rule Win_Trojan_TrojanFakeav_1
{
strings:
	$a0 = { 558bec83c4f0b86c551f16e8cc06f7ff33c05568d5591f16 }

	$a1 = { 6e646f77735c62627570646174652e746d70 }


condition:
	$a0 and $a1
}