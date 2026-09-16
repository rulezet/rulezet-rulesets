rule Win_Trojan_R_53
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0d32e42ac00d0503c1e310cd16c38beeb066b466cd2181fb666674 }


condition:
	$a0
}