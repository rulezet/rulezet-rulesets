rule Win_Trojan_Small_4330
{
strings:
	$a0 = { e8??000000[0-255]bb6764b20f81f36764f20f81e889f226262d77c9d8d98d[0-30]34ff0000 }


condition:
	$a0
}