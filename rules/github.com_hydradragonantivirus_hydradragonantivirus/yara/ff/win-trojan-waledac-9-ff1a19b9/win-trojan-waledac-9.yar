rule Win_Trojan_Waledac_9
{
strings:
	$a0 = { 558bec81eca00100008d956cffffff52ff15b4 }


condition:
	$a0
}