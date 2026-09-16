rule Win_Trojan_Mini3_2
{
strings:
	$a0 = { 0143b8005750cd215152b44033d2b94c01cd21b000e88e00b440ba4b01b90400cd215a5958 }


condition:
	$a0
}