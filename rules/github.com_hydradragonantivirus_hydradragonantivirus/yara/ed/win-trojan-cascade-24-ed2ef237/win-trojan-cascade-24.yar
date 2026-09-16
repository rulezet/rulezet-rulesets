rule Win_Trojan_Cascade_24
{
strings:
	$a0 = { 89e5e800005b81eb????2ef6872a0101fa740f8db74d01bc????31243134464c75f8 }


condition:
	$a0
}