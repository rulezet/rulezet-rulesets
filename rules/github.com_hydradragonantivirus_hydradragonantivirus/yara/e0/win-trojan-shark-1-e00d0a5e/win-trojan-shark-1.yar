rule Win_Trojan_Shark_1
{
strings:
	$a0 = { cf00000000e800005e81eec60083ee032e8c063601b803fecd213dfe037472b430cd213c03766a8cc34b8edb33ff80 }


condition:
	$a0
}