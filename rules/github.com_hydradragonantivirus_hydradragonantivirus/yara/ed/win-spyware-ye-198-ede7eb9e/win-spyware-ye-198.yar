rule Win_Spyware_ye_198
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]c309cd1ade85305a04a9d4c6ee8b3b }


condition:
	$a0
}