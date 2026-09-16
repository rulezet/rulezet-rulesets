rule Win_Trojan_Peed_194
{
strings:
	$a0 = { eb618d051245a500ba55e4a40089c15879255589e55189e68b5d188d63045089 }


condition:
	$a0
}