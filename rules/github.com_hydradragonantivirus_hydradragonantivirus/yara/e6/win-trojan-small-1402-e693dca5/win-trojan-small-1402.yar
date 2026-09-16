rule Win_Trojan_Small_1402
{
strings:
	$a0 = { 81eca40000005355565768483240006a006a00ff1528204000 }


condition:
	$a0
}