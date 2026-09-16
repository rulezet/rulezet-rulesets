rule Win_Trojan_PSFL_1
{
strings:
	$a0 = { 0fb045aabf000fb054aa32edb40532f6b280cd13fec580fdffe0f1b430b99a02cd2181f9bc01 }


condition:
	$a0
}