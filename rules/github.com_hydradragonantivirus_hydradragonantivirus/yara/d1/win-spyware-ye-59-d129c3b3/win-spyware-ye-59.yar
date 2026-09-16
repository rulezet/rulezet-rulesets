rule Win_Spyware_ye_59
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]3886429753722557792649b3d3f0a0 }


condition:
	$a0
}