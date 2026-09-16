rule Win_Spyware_ye_150
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]93599d6aaed5802a547924963e5b0b }


condition:
	$a0
}