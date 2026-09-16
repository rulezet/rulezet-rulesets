rule Win_Trojan_Gula_8
{
strings:
	$a0 = { 7374204449452021075589e5b848009acd02cf0083ec48bf15020e57b83f00508d7ed416579a }


condition:
	$a0
}