rule Win_Trojan_Quish_4
{
strings:
	$a0 = { 32028d7cff8db63202a48bf7e2e3c3eb18e8ceffb440b94a018d960001cd21fe862301eb00e8 }


condition:
	$a0
}