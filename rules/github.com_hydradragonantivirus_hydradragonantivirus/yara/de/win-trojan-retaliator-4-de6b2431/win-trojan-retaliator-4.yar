rule Win_Trojan_Retaliator_4
{
strings:
	$a0 = { 0e1fb41aba0000cd21e87d017503e8fd01e88e02e8da027403e91602e823007206e88f00e8f802061fba8000b41acd }


condition:
	$a0
}