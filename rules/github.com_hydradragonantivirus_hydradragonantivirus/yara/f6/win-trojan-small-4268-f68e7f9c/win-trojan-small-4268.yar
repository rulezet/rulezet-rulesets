rule Win_Trojan_Small_4268
{
strings:
	$a0 = { 565805dc090000505f8d2d335adbfce8????????ba5a00000052[0-200]608d5c2420 }


condition:
	$a0
}