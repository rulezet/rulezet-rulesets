rule Win_Trojan_Jocker_2
{
strings:
	$a0 = { e581ec0001bf00000e57bf401b1e57 }


condition:
	$a0
}