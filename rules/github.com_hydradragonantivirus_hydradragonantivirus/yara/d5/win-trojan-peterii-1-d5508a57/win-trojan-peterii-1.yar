rule Win_Trojan_PeterII_1
{
strings:
	$a0 = { 0e1f33c08ec08ed0bc007c26832e130404fb0e07b90300 }


condition:
	$a0
}