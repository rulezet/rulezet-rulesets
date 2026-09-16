rule Win_Trojan_IRC_2
{
strings:
	$a0 = { 6d4952430746fec0af66617a65722171be8e6c1c2e8173208370f6a34d8cd517 }


condition:
	$a0
}