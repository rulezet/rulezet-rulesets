rule Win_Trojan_Morgana_1
{
strings:
	$a0 = { 5e8d5c6ab9580681e96d0081e91e002e8a64382e302743e2fa }


condition:
	$a0
}