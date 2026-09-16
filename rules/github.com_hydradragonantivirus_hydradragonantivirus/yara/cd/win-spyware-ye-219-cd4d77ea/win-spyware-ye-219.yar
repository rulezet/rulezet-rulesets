rule Win_Spyware_ye_219
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]d826e237f392c5f799c6e9d3f390c0 }


condition:
	$a0
}