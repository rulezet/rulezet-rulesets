rule Win_Trojan_Morgan_1
{
strings:
	$a0 = { bf00008ab6d90230b39f0247e2f9c38b86d50289862c038b }


condition:
	$a0
}