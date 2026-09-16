rule Win_Trojan_Birgit_43
{
strings:
	$a0 = { 1601b91c002e8ab64a012e8a2732e62e882743e2f5c3 }


condition:
	$a0
}