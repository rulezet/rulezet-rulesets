rule Win_Trojan_Skew_2
{
strings:
	$a0 = { 51525653558bec33c98ec180fc4b7413fa26c706 }


condition:
	$a0
}