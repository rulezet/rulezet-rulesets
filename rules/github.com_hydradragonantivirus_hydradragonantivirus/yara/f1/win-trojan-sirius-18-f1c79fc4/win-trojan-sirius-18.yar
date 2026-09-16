rule Win_Trojan_Sirius_18
{
strings:
	$a0 = { 497fb7fd808d1420fe79d06e0743b3d60d6a6d2990aa9b6ac0798020bc1427c205d884133042cb80 }


condition:
	$a0
}