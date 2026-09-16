rule Win_Trojan_Tan_1
{
strings:
	$a0 = { b430cd213ddefa74445681c6870581ee03012ec604585e0e1f8bee5681ed0301b9ff00e817047224bf00018b }


condition:
	$a0
}