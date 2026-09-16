rule Win_Trojan_Stinkfoot_2
{
strings:
	$a0 = { be0000b92f0080b442014e46e2f8c3be }


condition:
	$a0
}