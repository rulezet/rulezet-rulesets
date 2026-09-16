rule Win_Spyware_ye_123
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]7846825793326517b9e6897313b0e0 }


condition:
	$a0
}