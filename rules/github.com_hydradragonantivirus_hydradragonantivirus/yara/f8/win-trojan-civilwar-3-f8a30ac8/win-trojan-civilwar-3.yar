rule Win_Trojan_CivilWar_3
{
strings:
	$a0 = { e800005d81ed07018db67f01bf0001a5a4b41a8d968201cd21b44e8d967601cd217305bb0001ffe38d96a001b8023dcd2193b43fb903008d967f01cd }


condition:
	$a0
}