rule Win_Spyware_ye_52
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]31ff3b884c6b1e486a17ba2c547121 }


condition:
	$a0
}