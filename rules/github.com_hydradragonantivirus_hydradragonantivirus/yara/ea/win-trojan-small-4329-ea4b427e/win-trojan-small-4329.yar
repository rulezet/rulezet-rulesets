rule Win_Trojan_Small_4329
{
strings:
	$a0 = { e8??000000e8??000000[0-255]5681ee04f6ffff5656585f }


condition:
	$a0
}