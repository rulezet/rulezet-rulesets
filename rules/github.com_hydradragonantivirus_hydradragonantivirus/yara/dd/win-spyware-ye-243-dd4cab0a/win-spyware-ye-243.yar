rule Win_Spyware_ye_243
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]f03efacf0baadd8f315e01eb8b2858 }


condition:
	$a0
}