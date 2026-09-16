rule Win_Trojan_BW_2
{
strings:
	$a0 = { bbc202bea8002e8107a86983c3024e75f5 }


condition:
	$a0
}