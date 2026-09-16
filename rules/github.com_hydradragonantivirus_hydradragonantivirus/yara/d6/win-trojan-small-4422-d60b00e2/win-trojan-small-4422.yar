rule Win_Trojan_Small_4422
{
strings:
	$a0 = { 0d??7640005050682c6a35f3e8660000005268??824000e8 }


condition:
	$a0
}