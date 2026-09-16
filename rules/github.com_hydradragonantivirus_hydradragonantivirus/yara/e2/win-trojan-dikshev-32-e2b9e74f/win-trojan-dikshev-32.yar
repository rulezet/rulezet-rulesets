rule Win_Trojan_Dikshev_32
{
strings:
	$a0 = { b44eb19e87cecd2173039090c3bf3b0157acaa3c2e75fabe370166a55ab45bcd21720b909093b440ba3b009087d1 }


condition:
	$a0
}