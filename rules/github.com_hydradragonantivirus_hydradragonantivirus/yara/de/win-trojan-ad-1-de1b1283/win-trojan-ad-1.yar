rule Win_Trojan_AD_1
{
strings:
	$a0 = { 40b9840090555acd21b8004233c933d2cd215e568b441a }


condition:
	$a0
}