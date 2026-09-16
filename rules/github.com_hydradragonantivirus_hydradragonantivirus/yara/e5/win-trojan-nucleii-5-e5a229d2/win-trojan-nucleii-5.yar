rule Win_Trojan_Nucleii_5
{
strings:
	$a0 = { b801578b1e4e038b0e56038b165403cd21b801438b0e5203ba3b03cd21b43bbaec02cd21b4 }


condition:
	$a0
}