rule Win_Trojan_Nuker_6
{
strings:
	$a0 = { bb00008db71201b943032e311c83c602e2f8 }


condition:
	$a0
}