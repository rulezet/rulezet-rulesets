rule Win_Trojan_DutchTiny_2
{
strings:
	$a0 = { 53501e3d004b7535b8023de8e7ff722d930e1fb43fcd21 }


condition:
	$a0
}