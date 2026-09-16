rule Win_Spyware_ye_230
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]e329ed3afea5d0faa4c9f4e68e2b5b }


condition:
	$a0
}