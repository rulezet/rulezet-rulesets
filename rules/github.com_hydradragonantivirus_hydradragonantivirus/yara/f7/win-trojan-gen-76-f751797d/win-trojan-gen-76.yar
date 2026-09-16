rule Win_Trojan_Gen_76
{
strings:
	$a0 = { 2500f03d00f0745f83c31e8bd3b43db002cd218bd8 }


condition:
	$a0
}