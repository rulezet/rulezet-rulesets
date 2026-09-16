rule Win_Trojan_R_51
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0ab403b005bb0000cd16c38beeb86666cd2181fb666674720e1fb4 }


condition:
	$a0
}