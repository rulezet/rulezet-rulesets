rule Win_Spyware_ye_63
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]3c824693577e29537d224dbfe78cc4 }


condition:
	$a0
}