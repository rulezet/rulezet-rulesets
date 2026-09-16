rule Win_Trojan_LightGeneral_1
{
strings:
	$a0 = { 01b92404b440cd2133d22689551526895517c3b82012 }


condition:
	$a0
}