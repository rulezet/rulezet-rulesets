rule Win_Trojan_VGEN_594
{
strings:
	$a0 = { e80000582d130189c58db62803bf0001a5a4b41aba00f9cd21b44e8d96220333c9cd21730db41aba8000cd21bb0001 }


condition:
	$a0
}