rule Win_Trojan_Little_BroG_1
{
strings:
	$a0 = { bf00018bf7b93301f3a48ed9be8400bf3302ba3501 }


condition:
	$a0
}