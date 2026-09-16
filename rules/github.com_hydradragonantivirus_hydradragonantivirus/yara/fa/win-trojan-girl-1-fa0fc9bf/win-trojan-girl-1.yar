rule Win_Trojan__Girl_1
{
strings:
	$a0 = { f1000800bef205bf0001b99600acaae2fcbe9601b90a }


condition:
	$a0
}