rule Win_Spyware_ye_91
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]58a662b77312457719466953731040 }


condition:
	$a0
}