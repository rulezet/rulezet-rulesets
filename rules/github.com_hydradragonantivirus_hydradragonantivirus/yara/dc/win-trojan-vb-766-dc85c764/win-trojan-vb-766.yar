rule Win_Trojan_VB_766
{
strings:
	$a0 = { 606a00ff15bcf1410081f0b4050000d2f885c30fbeeae80000000081ee2ad3540487dac1e17cf25981c1fe }


condition:
	$a0
}