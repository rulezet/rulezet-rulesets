rule Win_Trojan_Startpage_501
{
strings:
	$a0 = { 558bec83c4f0b884a25000e82c005b28a1880051008b00e82c07aa60a1880051 }


condition:
	$a0
}