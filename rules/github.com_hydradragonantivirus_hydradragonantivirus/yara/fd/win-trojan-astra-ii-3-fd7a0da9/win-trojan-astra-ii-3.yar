rule Win_Trojan_Astra_II_3
{
strings:
	$a0 = { 5d81ed0300e83f03b67f4ac1c135cb0682c0f3c34a33ee786bf587e1c135644cce8849eec35c0cc3644cceb449 }


condition:
	$a0
}