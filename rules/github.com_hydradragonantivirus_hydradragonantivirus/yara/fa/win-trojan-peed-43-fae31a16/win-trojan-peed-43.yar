rule Win_Trojan_Peed_43
{
strings:
	$a0 = { 89c189e58b6d1cc1ed0505624503004d }


condition:
	$a0
}