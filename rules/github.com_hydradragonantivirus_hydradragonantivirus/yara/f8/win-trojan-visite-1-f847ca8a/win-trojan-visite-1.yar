rule Win_Trojan_Visite_1
{
strings:
	$a0 = { 9e008bd3cd21725e9333c0b80057cd215152b8004233c933d2cd217249b440b9e800ba0001cd21 }


condition:
	$a0
}