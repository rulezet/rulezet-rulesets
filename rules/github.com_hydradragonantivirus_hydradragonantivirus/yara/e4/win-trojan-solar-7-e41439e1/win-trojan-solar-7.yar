rule Win_Trojan_Solar_7
{
strings:
	$a0 = { 8b4408034416c1e0042bc8874c142e890e2400619c2eff1d601eb4400e1f998bcf9cff1d }


condition:
	$a0
}