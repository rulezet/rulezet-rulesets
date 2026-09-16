rule Win_Trojan_Leprosy_53
{
strings:
	$a0 = { 8a2f322e0201882f4381fb2abc7ef159c3 }


condition:
	$a0
}