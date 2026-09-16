rule Win_Trojan_PS_50
{
strings:
	$a0 = { 1801b9eb022e8a272e32a619042e882743e2f2c3 }


condition:
	$a0
}