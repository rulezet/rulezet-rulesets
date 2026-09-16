rule Win_Trojan_Fletan_2
{
strings:
	$a0 = { e800005e83c6fd33dbb86969cd2181fb69697503e9 }


condition:
	$a0
}