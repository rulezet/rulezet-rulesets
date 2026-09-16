rule Win_Trojan_China_1
{
strings:
	$a0 = { 7504b0ff9dcf3d004b74069d2eff2e0d0050535152 }


condition:
	$a0
}