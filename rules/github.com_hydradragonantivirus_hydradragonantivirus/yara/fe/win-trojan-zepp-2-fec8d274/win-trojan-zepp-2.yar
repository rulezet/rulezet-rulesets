rule Win_Trojan_Zepp_2
{
strings:
	$a0 = { c605fca3400001e8e8190000c605fca3400000e8dc1900005589e581ec5c0200008dbdacfdffff576a3f68586040 }


condition:
	$a0
}