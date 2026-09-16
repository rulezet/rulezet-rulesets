rule Win_Spyware_ye_187
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]b806c217d3f2a5d7f9a6c933537020 }


condition:
	$a0
}