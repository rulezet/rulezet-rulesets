rule Win_Spyware_ye_9
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]06d410e521406b1d47741f89294e06 }


condition:
	$a0
}