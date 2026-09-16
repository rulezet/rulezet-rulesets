rule Win_Trojan_Tan_2
{
strings:
	$a0 = { b430cd213ddefa744a9090905681c6060681ee03012ec604585e0e1f8bee5681ed0301b9ff00e88d04722790 }


condition:
	$a0
}