rule Win_Trojan_Kitana_12
{
strings:
	$a0 = { ba800041bb0003cd13803f85740cc747fe55aab8020387f3cd13c387f30e1fff0e1304cd12 }


condition:
	$a0
}