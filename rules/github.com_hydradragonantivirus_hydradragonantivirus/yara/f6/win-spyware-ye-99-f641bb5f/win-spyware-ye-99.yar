rule Win_Spyware_ye_99
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]60ae6abf7b1a4d7f214e715b7b1848 }


condition:
	$a0
}