rule Win_Trojan_ExtermV_1
{
strings:
	$a0 = { ba9e00b8023dcd217302eb128bd8e84a }


condition:
	$a0
}