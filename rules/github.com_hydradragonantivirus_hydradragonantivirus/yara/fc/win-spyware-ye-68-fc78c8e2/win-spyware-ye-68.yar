rule Win_Spyware_ye_68
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]418f4b985c7b2e587a274abce48131 }


condition:
	$a0
}