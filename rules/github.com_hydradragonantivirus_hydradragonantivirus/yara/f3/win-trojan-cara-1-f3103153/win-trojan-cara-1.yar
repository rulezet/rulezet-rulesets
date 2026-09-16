rule Win_Trojan_Cara_1
{
strings:
	$a0 = { 812e0200c000b44abb00b0cd2181ebc0 }


condition:
	$a0
}