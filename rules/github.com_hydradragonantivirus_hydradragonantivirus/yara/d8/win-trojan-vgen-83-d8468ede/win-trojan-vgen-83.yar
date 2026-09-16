rule Win_Trojan_VGEN_83
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb08b8050333dbcd16c38beeb86666cd2181fb6666745a0e1fb44abb }


condition:
	$a0
}