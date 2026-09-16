rule Win_Spyware_ye_29
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]1ae024f1355c0fb9db8023953d5a0a }


condition:
	$a0
}