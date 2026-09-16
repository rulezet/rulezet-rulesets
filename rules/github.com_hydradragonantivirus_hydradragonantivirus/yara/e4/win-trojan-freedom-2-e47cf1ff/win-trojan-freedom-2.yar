rule Win_Trojan_Freedom_2
{
strings:
	$a0 = { 8d96ad04e8ec003e8186b204b403b440b9b40333d2e8db00b8004233c933d2e8d100b440b9 }


condition:
	$a0
}