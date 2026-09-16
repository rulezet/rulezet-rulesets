rule Win_Spyware_ye_103
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]64aa6ebb7f26517b254a75670fb4ec }


condition:
	$a0
}