rule Win_Trojan_Small_4342
{
strings:
	$a0 = { e8??000000(e9|e8)??000000[0-255]5681ee64f6ffff5656585f8d4900 }


condition:
	$a0
}