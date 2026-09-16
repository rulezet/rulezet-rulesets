rule Win_Spyware_ye_206
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]cb11d522e68d38620cb1dccef693c3 }


condition:
	$a0
}