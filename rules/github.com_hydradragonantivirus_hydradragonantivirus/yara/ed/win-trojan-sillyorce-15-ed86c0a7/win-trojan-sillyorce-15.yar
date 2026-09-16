rule Win_Trojan_SillyORCE_15
{
strings:
	$a0 = { 80fc3e751c1e52515033c933d2b80042cdffb1610e1fb440cdff58cdff595a1fcfea }


condition:
	$a0
}