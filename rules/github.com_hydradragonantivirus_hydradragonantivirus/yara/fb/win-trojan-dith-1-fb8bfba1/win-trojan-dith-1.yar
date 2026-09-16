rule Win_Trojan_Dith_1
{
strings:
	$a0 = { bb0000b8004b9c2eff1e18002e8b166f00b80031cd21 }


condition:
	$a0
}