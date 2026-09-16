rule Win_Trojan_Small_4381
{
strings:
	$a0 = { e8??000000e8??0000008d2d1a????05 }


condition:
	$a0
}