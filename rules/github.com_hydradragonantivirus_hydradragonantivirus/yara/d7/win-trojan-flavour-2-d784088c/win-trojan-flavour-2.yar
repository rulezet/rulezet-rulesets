rule Win_Trojan_Flavour_2
{
strings:
	$a0 = { 2e2501cf32c0cfcfe81c009cfa2eff1e2d01c3e811009cfa2eff1e2901c3b44233c999e8edff }


condition:
	$a0
}