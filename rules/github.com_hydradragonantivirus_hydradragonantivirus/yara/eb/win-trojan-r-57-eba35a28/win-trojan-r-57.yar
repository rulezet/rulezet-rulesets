rule Win_Trojan_R_57
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb09b80503c1e310cd16c38beeb066b466cd2181fb666674680e1fb7 }


condition:
	$a0
}