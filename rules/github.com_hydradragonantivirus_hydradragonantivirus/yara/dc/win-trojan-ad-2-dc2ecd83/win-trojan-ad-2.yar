rule Win_Trojan_AD_2
{
strings:
	$a0 = { b99d0090555acd21b8004233c933d2cd215e568b441a }


condition:
	$a0
}