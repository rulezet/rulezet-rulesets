rule Win_Trojan_Small_4327
{
strings:
	$a0 = { e8??000000e9??000000[0-255]bb0000c0fff7d3ffc381e800440000 }


condition:
	$a0
}