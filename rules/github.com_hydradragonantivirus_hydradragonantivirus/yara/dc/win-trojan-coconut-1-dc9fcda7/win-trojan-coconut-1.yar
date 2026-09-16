rule Win_Trojan_Coconut_1
{
strings:
	$a0 = { ff833edb0500740ead2bc133c1d3c0abff0edb05ebeb }


condition:
	$a0
}