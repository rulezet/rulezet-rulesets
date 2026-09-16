rule Win_Trojan_Zbot_1230
{
strings:
	$a0 = { 535881f62e851cd189c283c21cf7d68b0a534a }

	$a1 = { 8b2a7e416034676f62696e }


condition:
	$a0 and $a1
}