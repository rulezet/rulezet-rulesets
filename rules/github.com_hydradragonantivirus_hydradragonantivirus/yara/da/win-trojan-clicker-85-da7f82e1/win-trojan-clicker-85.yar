rule Win_Trojan_Clicker_85
{
strings:
	$a0 = { 558bec6aff6800000000680000000064a1000000005064892500000000e83fffffff525150e885ff }


condition:
	$a0
}