rule Win_Trojan_HWF_1
{
strings:
	$a0 = { 2f000e85c71fb9a92f517c0081c1b2d358909000079090fcfa4348e2f6 }


condition:
	$a0
}