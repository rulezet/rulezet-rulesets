rule Win_Trojan_Birgit_14
{
strings:
	$a0 = { 1601b944002e8ab672012e8a2732e62e882743e2f5c3 }


condition:
	$a0
}