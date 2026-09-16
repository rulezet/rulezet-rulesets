rule Win_Trojan_L_50
{
strings:
	$a0 = { 01cd21725093b4408d94c000b9b87bcd21b43ecd218cc0488ed88b1e03000e1f5381eb0019b4 }


condition:
	$a0
}