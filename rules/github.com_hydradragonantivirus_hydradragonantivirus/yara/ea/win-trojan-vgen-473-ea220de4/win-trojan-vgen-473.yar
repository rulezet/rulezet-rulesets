rule Win_Trojan_VGEN_473
{
strings:
	$a0 = { 018b048bf0e8480233c08ec026a184008984510326a1860089845303b43dbfff55baff51cd2181ff55ff7456b461 }


condition:
	$a0
}