rule Win_Trojan_Stoned_34
{
strings:
	$a0 = { 13b8010333dbb90100cd1333c08ed8b8f100a34c00c7064e00809fb404cd1a81fa0412750cb88a }


condition:
	$a0
}