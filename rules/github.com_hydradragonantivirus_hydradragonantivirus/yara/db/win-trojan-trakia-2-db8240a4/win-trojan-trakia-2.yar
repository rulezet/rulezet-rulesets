rule Win_Trojan_Trakia_2
{
strings:
	$a0 = { 023dcd21930e1fb43fba2d02b91800cd2133c933d2b802 }


condition:
	$a0
}