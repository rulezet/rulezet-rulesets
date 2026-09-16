rule Win_Trojan_Kriz_4
{
strings:
	$a0 = { 509c60be2e8333004a494dbf4400000081c330000000e805 }


condition:
	$a0
}