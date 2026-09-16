rule Win_Trojan_Majkl_3
{
strings:
	$a0 = { 01bf0b9481fec30177149090eb0590263e3f2e81c70b982e313a4646ebe6 }


condition:
	$a0
}