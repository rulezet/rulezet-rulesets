rule Win_Trojan_Trivial_232
{
strings:
	$a0 = { ba000193b12acd21b43ecd21b44f }


condition:
	$a0
}