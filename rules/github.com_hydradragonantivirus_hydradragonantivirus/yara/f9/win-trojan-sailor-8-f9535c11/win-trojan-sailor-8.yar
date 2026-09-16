rule Win_Trojan_Sailor_8
{
strings:
	$a0 = { b80e33d232c0e86e00061f5e730483c40ac3b44051e895fc2ac0e85cff59581f5a803ecc0e0274 }


condition:
	$a0
}