rule Win_Trojan_AntiCAD_5
{
strings:
	$a0 = { c02e8b16460e33db2e8b0e440eb80802 }


condition:
	$a0
}