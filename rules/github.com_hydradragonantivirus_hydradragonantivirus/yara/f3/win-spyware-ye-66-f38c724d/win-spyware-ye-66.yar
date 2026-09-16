rule Win_Spyware_ye_66
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]3f8d499e5a792c5e00add03a5a7f37 }


condition:
	$a0
}