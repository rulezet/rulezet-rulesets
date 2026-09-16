rule Win_Spyware_ye_193
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]be0cc81dd9f8a3d5ffacd7c1e1863e }


condition:
	$a0
}