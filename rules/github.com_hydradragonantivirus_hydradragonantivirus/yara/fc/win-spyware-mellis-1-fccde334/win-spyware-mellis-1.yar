rule Win_Spyware_Mellis_1
{
strings:
	$a0 = { 4b45594c4f472100000000010000085642 }

	$a1 = { 38be00ea01b8004b65794c6f6721202856657273696f6e20322e }


condition:
	$a0 and $a1
}