rule Win_Trojan_Pklite_1
{
strings:
	$a0 = { ac0dbabf033be07319befe018ccb81c300108ec3bf0000b92800fcf3a40633c050cb5006b80052cd21268e47fe }


condition:
	$a0
}