rule Win_Spyware_ye_83
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]509e5aaf6b0abdef913e614b6b08b8 }


condition:
	$a0
}