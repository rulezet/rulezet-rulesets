rule Win_Trojan_Peed_346
{
strings:
	$a0 = { 2d10ab22004ee84500000051eb0b83c8ff83c0fd29c249eb46b9fa00000089d7 }


condition:
	$a0
}