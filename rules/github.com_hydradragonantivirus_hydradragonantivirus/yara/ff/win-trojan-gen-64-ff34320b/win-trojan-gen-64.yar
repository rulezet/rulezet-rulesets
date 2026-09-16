rule Win_Trojan_Gen_64
{
strings:
	$a0 = { 018a2f322e0301882f4381fb0009 }


condition:
	$a0
}