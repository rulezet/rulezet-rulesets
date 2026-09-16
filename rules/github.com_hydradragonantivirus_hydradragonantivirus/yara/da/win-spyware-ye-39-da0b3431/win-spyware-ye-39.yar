rule Win_Spyware_ye_39
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]24ea2efb3f6611bbe58a35a7cff4ac }


condition:
	$a0
}