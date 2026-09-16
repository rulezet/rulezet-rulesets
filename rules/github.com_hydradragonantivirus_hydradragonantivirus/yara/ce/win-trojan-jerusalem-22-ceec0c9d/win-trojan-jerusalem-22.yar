rule Win_Trojan_Jerusalem_22
{
strings:
	$a0 = { 2e8e1612002e8b2610002eff2e140058 }


condition:
	$a0
}