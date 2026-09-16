rule Win_Spyware_ye_20
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]11df1be82c4b7e284a771a8c345101 }


condition:
	$a0
}