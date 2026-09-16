rule Win_Trojan_Matthew_2
{
strings:
	$a0 = { 8ec026803eec03877410909026803eec037874069090 }


condition:
	$a0
}