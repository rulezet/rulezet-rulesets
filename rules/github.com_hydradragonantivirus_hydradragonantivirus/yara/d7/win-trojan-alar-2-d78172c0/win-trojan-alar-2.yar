rule Win_Trojan_Alar_2
{
strings:
	$a0 = { 2804262e4680c700e905004658140ab04b9cf8269d0f85e4ff }


condition:
	$a0
}