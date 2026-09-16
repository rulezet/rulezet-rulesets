rule Win_Trojan_Satan3_2
{
strings:
	$a0 = { 8ed8bf0001be1724b90500f3a4b4e8cd2180fcab7403eb3390bb00010e1fffe3 }


condition:
	$a0
}