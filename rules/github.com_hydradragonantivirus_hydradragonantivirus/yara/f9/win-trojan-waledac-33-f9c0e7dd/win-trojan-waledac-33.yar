rule Win_Trojan_Waledac_33
{
strings:
	$a0 = { 66d3fb4b12d180ce7585f2e8431600009310b2261fbcf2 }


condition:
	$a0
}