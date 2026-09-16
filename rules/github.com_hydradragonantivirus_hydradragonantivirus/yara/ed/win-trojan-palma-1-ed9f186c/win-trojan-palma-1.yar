rule Win_Trojan_Palma_1
{
strings:
	$a0 = { ba0001b9f700cd21b43ecd212ea0da013c0275052efe }


condition:
	$a0
}