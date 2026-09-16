rule Win_Trojan_Peed_338
{
strings:
	$a0 = { 8db4244223ff00e84500000048b9e3cbffff81c167450000 }


condition:
	$a0
}