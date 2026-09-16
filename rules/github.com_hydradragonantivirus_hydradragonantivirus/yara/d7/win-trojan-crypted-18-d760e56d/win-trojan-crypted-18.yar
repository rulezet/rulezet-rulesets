rule Win_Trojan_Crypted_18
{
strings:
	$a0 = { 558bec6aff684b435546685449485364a100000000506489250000000083ec68 }


condition:
	$a0
}