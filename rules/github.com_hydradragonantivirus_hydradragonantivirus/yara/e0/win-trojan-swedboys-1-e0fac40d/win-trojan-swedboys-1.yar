rule Win_Trojan_SwedBoys_1
{
strings:
	$a0 = { 018a27bb02018a0786c48bf0b41a8d94c802cd2133c9b44e }


condition:
	$a0
}