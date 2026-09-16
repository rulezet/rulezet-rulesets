rule Win_Trojan_Grog_30
{
strings:
	$a0 = { cd217303e9990093b80057cd215152e801004d5a8b }


condition:
	$a0
}