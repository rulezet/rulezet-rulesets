rule Win_Trojan_Small_5383
{
strings:
	$a0 = { e8??000000e8??0000008d2d1a974705 }


condition:
	$a0
}