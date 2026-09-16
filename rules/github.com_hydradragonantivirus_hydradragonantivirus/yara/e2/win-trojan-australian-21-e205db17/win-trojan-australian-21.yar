rule Win_Trojan_Australian_21
{
strings:
	$a0 = { 415aeced5591e8e2f31f48c1fcecbc }


condition:
	$a0
}