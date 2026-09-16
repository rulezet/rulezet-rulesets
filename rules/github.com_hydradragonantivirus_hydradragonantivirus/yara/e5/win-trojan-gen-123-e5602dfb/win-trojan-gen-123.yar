rule Win_Trojan_Gen_123
{
strings:
	$a0 = { d5a1cd213d0d907409b44abb0010cd }


condition:
	$a0
}