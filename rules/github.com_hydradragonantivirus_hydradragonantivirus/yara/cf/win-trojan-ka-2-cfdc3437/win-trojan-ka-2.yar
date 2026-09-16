rule Win_Trojan_KA_2
{
strings:
	$a0 = { 8b1e9b029c2eff1e8f02730458e968ffc3b4402e8b1e9b029c2eff1e8f02730458e954ffc3 }


condition:
	$a0
}