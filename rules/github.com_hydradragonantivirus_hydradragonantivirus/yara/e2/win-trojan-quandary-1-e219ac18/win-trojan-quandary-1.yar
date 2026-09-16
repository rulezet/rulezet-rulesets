rule Win_Trojan_Quandary_1
{
strings:
	$a0 = { bf2501051474782681bfbb0128c9743cb001e89400b801 }


condition:
	$a0
}