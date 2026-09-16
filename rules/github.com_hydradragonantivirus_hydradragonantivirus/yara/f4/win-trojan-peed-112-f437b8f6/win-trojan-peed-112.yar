rule Win_Trojan_Peed_112
{
strings:
	$a0 = { 686e93faffeb5fba010000004a87ca83c40583ec }


condition:
	$a0
}