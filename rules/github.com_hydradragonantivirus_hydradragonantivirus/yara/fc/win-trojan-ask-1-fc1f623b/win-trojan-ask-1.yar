rule Win_Trojan_Ask_1
{
strings:
	$a0 = { e800005b5383c31790ba0000b9f4012e3117e30643434949ebf5 }


condition:
	$a0
}