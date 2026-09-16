rule Win_Spyware_ye_253
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]fac004d115bcef993b6003f59d3a6a }


condition:
	$a0
}