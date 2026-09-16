rule Win_Trojan_Peed_72
{
strings:
	$a0 = { 558bec83ec0ce8d6fdffff85c00f84fc000000535657 }


condition:
	$a0
}