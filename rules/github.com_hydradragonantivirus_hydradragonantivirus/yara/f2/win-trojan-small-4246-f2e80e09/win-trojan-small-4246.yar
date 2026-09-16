rule Win_Trojan_Small_4246
{
strings:
	$a0 = { 29c98d9923????008d9bddeeddff53535f5d29c98db132 }


condition:
	$a0
}