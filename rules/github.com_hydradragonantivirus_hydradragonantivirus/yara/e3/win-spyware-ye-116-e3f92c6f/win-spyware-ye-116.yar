rule Win_Spyware_ye_116
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]71bf7b488c2b5e08aad7faec943161 }


condition:
	$a0
}