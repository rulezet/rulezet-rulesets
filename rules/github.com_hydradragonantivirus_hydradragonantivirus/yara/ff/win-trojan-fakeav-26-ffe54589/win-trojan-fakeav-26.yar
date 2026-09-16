rule Win_Trojan_Fakeav_26
{
strings:
	$a0 = { 558bec6aff689f20001468641e001464a10000000050648925 }

	$a1 = { 39373a2e514f536168656c }

	$a2 = { 291b3525501a50 }

	$a3 = { 3a1b256f2b6e }


condition:
	$a0 and $a1 and $a2 and $a3
}