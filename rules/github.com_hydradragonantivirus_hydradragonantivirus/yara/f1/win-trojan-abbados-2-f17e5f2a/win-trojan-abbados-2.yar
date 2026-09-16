rule Win_Trojan_Abbados_2
{
strings:
	$a0 = { 31??81??5589e58b74 }


condition:
	$a0
}