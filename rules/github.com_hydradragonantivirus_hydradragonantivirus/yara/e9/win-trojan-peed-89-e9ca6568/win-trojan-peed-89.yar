rule Win_Trojan_Peed_89
{
strings:
	$a0 = { 6bc900e802000000fcfc5a8d1d10??400029d2528b3b89e353ffd783c404bfa9 }


condition:
	$a0
}