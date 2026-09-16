rule Win_Trojan_Trojan_251
{
strings:
	$a0 = { fdb4decd2180fcdf7447c6067102 }


condition:
	$a0
}