rule Win_Trojan_Miny_4
{
strings:
	$a0 = { 4d01c6064f0143b8005750cd215152b44033d2b94d01cd21b000e88e00b440ba4c01b90400cd21 }


condition:
	$a0
}