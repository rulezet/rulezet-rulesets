rule Win_Spyware_ye_173
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]aa70b401c5ec9fc9eb9033a5cdea9a }


condition:
	$a0
}