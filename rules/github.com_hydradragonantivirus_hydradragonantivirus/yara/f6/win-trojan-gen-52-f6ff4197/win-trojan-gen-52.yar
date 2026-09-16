rule Win_Trojan_Gen_52
{
strings:
	$a0 = { 7f080375088bd8837f0601740f8b5efc837f0c057541837f }


condition:
	$a0
}