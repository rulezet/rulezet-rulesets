rule Win_Trojan_PrintDevil_1
{
strings:
	$a0 = { 03be2401bf7603e81f00b440ba0001b9cc029c2eff1eb6039c2e8a26ba03be2401e80500 }


condition:
	$a0
}