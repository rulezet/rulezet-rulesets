rule Win_Spyware_ye_65
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]3e8c489d597823557f2c57416106be }


condition:
	$a0
}