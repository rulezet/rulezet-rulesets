rule Win_Spyware_ye_143
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]8c529663a7cef9a3cdf29d0fb7dc94 }


condition:
	$a0
}