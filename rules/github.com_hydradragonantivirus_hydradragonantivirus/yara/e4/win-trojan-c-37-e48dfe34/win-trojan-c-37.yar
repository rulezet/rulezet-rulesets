rule Win_Trojan_C_37
{
strings:
	$a0 = { 434f890783c302b84d008907b90300b45bcd2172160e1fba0001b97e0181e900018bd8b440cd21 }


condition:
	$a0
}