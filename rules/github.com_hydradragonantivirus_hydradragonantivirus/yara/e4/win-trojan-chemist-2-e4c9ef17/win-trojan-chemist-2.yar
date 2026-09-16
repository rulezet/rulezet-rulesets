rule Win_Trojan_Chemist_2
{
strings:
	$a0 = { befe018904b90901bafa01b44050cd2133c933d2b80042cd21b90300bafd0158cd21be9503 }


condition:
	$a0
}