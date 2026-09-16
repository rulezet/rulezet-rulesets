rule Win_Spyware_ye_179
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]b07eba0fcbea9dcff19ec12b4b6818 }


condition:
	$a0
}