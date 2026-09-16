rule Win_Trojan_Xtc_1
{
strings:
	$a0 = { 0e1fb97f1f8bd981c1d3e881c397e08137????43e2f9 }


condition:
	$a0
}