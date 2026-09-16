rule Win_Trojan_Skism_2
{
strings:
	$a0 = { 5de80300e9e70551bb38018a2f322e0301882f4381fb00097ef159c3 }


condition:
	$a0
}