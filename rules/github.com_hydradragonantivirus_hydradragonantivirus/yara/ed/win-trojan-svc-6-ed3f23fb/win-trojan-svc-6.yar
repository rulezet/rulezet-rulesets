rule Win_Trojan_SVC_6
{
strings:
	$a0 = { 5e81ee03012e89844d0d065633d2b41480c470cd215e5681fa941975262e3abc760d771c721d560686e035ffff8ec0 }


condition:
	$a0
}