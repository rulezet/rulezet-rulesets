rule Win_Trojan_Buzus_49
{
strings:
	$a0 = { e859280000e916feffff558bec83ec04897dfc8b7d088b4d0cc1e907660fefc0 }


condition:
	$a0
}