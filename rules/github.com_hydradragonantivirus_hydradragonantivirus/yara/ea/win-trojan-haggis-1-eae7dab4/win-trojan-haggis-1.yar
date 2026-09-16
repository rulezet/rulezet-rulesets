rule Win_Trojan_Haggis_1
{
strings:
	$a0 = { 010100558e02000000ffff090300002c010000050000000903 }


condition:
	$a0
}