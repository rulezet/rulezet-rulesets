rule Win_Spyware_ye_175
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]ac72b603c7ee99c3ed923dafd7fcb4 }


condition:
	$a0
}