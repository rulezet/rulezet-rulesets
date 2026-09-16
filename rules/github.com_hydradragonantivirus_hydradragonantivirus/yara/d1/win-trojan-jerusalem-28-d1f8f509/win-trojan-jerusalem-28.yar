rule Win_Trojan_Jerusalem_28
{
strings:
	$a0 = { 2eff1e20013dffac7514b863ec2e8b0e0701bf00 }


condition:
	$a0
}