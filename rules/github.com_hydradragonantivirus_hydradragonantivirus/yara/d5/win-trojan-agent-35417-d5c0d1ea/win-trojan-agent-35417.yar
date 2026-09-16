rule Win_Trojan_Agent_35417
{
strings:
	$a0 = { 558bec6aff6850d340006890c7400064a10000000050648925 }

	$a1 = { 7a7b7475767770714c4c4c714c4c4c4c4d4e }


condition:
	$a0 and $a1
}