rule Win_Spyware_ye_28
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]19e723f0345306b0d2ffa214bcd989 }


condition:
	$a0
}