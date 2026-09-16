rule Win_Trojan_LCV_1
{
strings:
	$a0 = { 248b1e2201ba00018b0e3001b440cd }


condition:
	$a0
}