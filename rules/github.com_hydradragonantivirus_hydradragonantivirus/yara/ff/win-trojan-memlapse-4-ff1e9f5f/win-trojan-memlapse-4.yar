rule Win_Trojan_MemLapse_4
{
strings:
	$a0 = { e800005d81ed0301065f83c7102e03be6302572effb66102061e0e2bc05050071fbe8400bf0c00a5a51fb430cc3c03722bb41a8d966f02ccc6866e0203b44eb9 }


condition:
	$a0
}