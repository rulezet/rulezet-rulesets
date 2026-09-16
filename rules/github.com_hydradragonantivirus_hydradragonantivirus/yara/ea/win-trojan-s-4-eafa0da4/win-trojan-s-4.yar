rule Win_Trojan_S_4
{
strings:
	$a0 = { f646268b0ce302ebf88bd683c204e8 }


condition:
	$a0
}