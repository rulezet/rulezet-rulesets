rule Win_Trojan_C_91
{
strings:
	$a0 = { 7307a39cc4d1eb09c706da08f2e1d8deff56060306e483d2fff0008bc80bd2751081c1d0720a3b }


condition:
	$a0
}