rule Win_Spyware_ye_35
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]20ee2aff3b5a0dbfe18e319b3b5808 }


condition:
	$a0
}