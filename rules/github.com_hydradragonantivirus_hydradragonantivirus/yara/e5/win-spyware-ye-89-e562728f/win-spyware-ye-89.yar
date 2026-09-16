rule Win_Spyware_ye_89
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]56a460b57110bbed97c4efd9f99ed6 }


condition:
	$a0
}