rule Win_Trojan_Peed_110
{
strings:
	$a0 = { b887d61200e99c00000089daf7da01d0ba2200000083f8007466c3f7db29dff7 }


condition:
	$a0
}