rule Win_Trojan_Raving_1
{
strings:
	$a0 = { b403cd1089165f01cc90b80000a26a01a1980287c1b44ebe920287d6cd21be9e00bf3f023d00007409a26a0133c0 }


condition:
	$a0
}