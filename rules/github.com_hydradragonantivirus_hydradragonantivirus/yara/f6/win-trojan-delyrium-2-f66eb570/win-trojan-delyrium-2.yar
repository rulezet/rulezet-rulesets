rule Win_Trojan_Delyrium_2
{
strings:
	$a0 = { b440b9f206ba0001e8cb00e9c100b42a }


condition:
	$a0
}