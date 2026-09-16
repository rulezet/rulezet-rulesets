rule Win_Trojan_Peed_37
{
strings:
	$a0 = { 89e58d651c5f89ec83c0024f83e80183 }


condition:
	$a0
}