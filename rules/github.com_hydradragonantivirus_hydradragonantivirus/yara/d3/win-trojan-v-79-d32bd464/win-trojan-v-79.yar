rule Win_Trojan_V_79
{
strings:
	$a0 = { 02cd21b8dcfecd2181f9dada744f0633c08ed8c43e84 }


condition:
	$a0
}