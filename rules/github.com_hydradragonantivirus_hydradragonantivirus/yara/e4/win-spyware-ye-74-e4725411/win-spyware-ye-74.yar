rule Win_Spyware_ye_74
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]479551a66201b4e6883558426207bf }


condition:
	$a0
}