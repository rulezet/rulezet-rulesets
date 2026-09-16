rule Win_Trojan_FatherMac_3
{
strings:
	$a0 = { b9a60681e9280188e488d2268a0288e480ef00342089 }


condition:
	$a0
}