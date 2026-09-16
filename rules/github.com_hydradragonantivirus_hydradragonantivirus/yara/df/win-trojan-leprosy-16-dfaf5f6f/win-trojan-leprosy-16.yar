rule Win_Trojan_Leprosy_16
{
strings:
	$a0 = { eb579051bb3b018a2f322e0301882f4381fb99027ef1 }


condition:
	$a0
}