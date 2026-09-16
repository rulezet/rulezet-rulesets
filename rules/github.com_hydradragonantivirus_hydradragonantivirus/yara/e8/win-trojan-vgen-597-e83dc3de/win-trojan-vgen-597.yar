rule Win_Trojan_VGEN_597
{
strings:
	$a0 = { 1100bba2015053cb9090909090c80002008bfcb130be53010e0e071ff3a4b1e733c0f3abb855aaabb8010341ba }


condition:
	$a0
}