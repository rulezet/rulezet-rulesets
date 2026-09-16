rule Win_Trojan_SillyRC_36
{
strings:
	$a0 = { be5634cd210bdb7532e440a807751a33db8ae8e440 }


condition:
	$a0
}