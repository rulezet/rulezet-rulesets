rule Win_Trojan_VB_1736
{
strings:
	$a0 = { 6d65737465616465720000f4010000847c40 }


condition:
	$a0
}