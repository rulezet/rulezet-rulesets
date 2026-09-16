rule Win_Spyware_ye_47
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]2cf23683476e19436d12bd2f577c34 }


condition:
	$a0
}