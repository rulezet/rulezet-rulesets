rule Win_Spyware_ye_80
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]4d9357ac680fbaec963b665070154d }


condition:
	$a0
}