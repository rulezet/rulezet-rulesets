rule Win_Trojan_Eliza_2
{
strings:
	$a0 = { 81c60001bf0001595156acaae2fc5f5932c0aae2fd }


condition:
	$a0
}