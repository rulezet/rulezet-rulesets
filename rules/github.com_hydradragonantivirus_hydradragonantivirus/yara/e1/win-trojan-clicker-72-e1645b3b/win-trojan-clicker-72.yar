rule Win_Trojan_Clicker_72
{
strings:
	$a0 = { 558bec6aff68483241006860 }

	$a1 = { 6d73746d70786d6c656e762e786d6c }

	$a2 = { 6d2f647265616d2e706870 }


condition:
	$a0 and $a1 and $a2
}