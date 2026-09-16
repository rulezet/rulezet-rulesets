rule Win_Trojan_Vundo_499
{
strings:
	$a0 = { c1d04e2537020000e9 }


condition:
	$a0
}