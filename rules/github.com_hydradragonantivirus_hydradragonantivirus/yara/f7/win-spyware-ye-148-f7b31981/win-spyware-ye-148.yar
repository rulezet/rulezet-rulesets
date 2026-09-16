rule Win_Spyware_ye_148
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]915f9b68accbfea8caf79a0cb4d181 }


condition:
	$a0
}