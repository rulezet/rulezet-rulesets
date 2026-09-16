rule Win_Trojan_Small_4312
{
strings:
	$a0 = { e8??000000e8??000000[0-255]bb6764b20f81f36764f20f????????????2d77c9d8d98d3405000000008d7433008db6 }


condition:
	$a0
}