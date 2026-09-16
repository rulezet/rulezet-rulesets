rule Win_Trojan_ICE_1
{
strings:
	$a0 = { ff743f80fc3d740580fc4b7530505351065657521e2e }


condition:
	$a0
}