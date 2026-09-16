rule Win_Trojan_LarryonaScreen_1
{
strings:
	$a0 = { 50cbbf00018b750181c6d90257b90500fcf3a481 }


condition:
	$a0
}