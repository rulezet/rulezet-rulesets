rule Win_Trojan_Zlob_2193
{
strings:
	$a0 = { bb00000000[0-150]8d1d1aa94000 }


condition:
	$a0
}