rule Win_Spyware_ye_153
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]9664a075b1d0fbadd7842f99395e16 }


condition:
	$a0
}