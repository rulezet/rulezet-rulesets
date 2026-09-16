rule Win_Trojan_Peed_79
{
strings:
	$a0 = { b870b240008d0c248b4c2100 }


condition:
	$a0
}