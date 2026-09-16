rule Win_Trojan_R_50
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0b2affb300b005b403cd16c38beeb066b466cd2181fb666674660e }


condition:
	$a0
}