rule Win_Trojan_VB_343
{
strings:
	$a0 = { 5068dc6740008b55088b028b4d0851ff90f8060000 }


condition:
	$a0
}