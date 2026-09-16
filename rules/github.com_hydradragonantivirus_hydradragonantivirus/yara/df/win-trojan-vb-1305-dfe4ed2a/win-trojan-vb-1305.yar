rule Win_Trojan_VB_1305
{
strings:
	$a0 = { 2d433030302d4e455754574f0030 }

	$a1 = { 6d6f6452756e00006d6f64456e6332006d6f64474f3200006d6f645a49 }


condition:
	$a0 and $a1
}