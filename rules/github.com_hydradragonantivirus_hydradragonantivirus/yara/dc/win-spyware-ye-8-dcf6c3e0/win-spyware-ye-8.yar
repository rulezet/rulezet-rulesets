rule Win_Spyware_ye_8
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]05cb0fe4204772244e731e88284d05 }


condition:
	$a0
}