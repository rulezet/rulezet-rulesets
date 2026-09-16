rule Win_Trojan_Gen_112
{
strings:
	$a0 = { b80000501ffaa104008946dca106008946dea10c008946e0 }


condition:
	$a0
}