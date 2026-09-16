rule Win_Trojan_Miny_9
{
strings:
	$a0 = { 0300a34101c606430143b44033d2b94101cd21b000e88700b440ba4001b90400cd21b43ecd2133 }


condition:
	$a0
}