rule Win_Trojan_Falus_1
{
strings:
	$a0 = { b99d048bd581ea0f01e8eafd72c6b8004233c9ba0100 }


condition:
	$a0
}