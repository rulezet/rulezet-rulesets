rule Win_Trojan_V_12
{
strings:
	$a0 = { b9030033d2e84a0172eeb8004233c98b160100e83c0172e0b440ba0300b9d90490e82e01ebd2 }


condition:
	$a0
}