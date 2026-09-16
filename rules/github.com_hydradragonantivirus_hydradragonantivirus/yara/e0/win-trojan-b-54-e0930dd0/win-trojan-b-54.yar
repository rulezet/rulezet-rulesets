rule Win_Trojan_B_54
{
strings:
	$a0 = { e1b92000be0b02bf0b00fcf3a4b8010333dbfec1fec6cd13ebc8 }


condition:
	$a0
}