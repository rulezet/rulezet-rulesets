rule Win_Trojan_Zlob_2192
{
strings:
	$a0 = { bf00000000[0-150]8d3d1aa94000 }


condition:
	$a0
}