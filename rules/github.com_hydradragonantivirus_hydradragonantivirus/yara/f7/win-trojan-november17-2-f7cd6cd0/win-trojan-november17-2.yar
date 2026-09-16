rule Win_Trojan_November17_2
{
strings:
	$a0 = { 0183fb007410fa8dbc2501b90104310d311d4743e2f8 }


condition:
	$a0
}