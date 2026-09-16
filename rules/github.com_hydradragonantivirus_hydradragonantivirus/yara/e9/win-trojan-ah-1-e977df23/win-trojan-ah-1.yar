rule Win_Trojan_Ah_1
{
strings:
	$a0 = { 294d038955028ec28d77fdb99504f3 }


condition:
	$a0
}