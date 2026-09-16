rule Win_Trojan_Betaboys_3
{
strings:
	$a0 = { 81ed03018d9e20018d968b013e8a8e03013bda7405300f }


condition:
	$a0
}