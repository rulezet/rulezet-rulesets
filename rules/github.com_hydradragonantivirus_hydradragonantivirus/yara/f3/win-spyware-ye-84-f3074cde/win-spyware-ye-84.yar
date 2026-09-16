rule Win_Spyware_ye_84
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]519f5ba86c0bbee88a375a4c741141 }


condition:
	$a0
}