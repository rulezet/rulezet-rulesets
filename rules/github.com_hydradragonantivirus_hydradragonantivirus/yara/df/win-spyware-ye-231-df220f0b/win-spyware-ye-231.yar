rule Win_Spyware_ye_231
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]e42aee3bffa6d1fba5caf5e78f346c }


condition:
	$a0
}