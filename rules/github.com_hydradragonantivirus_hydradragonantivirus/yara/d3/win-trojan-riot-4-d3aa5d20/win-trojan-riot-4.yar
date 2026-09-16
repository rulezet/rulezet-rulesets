rule Win_Trojan_Riot_4
{
strings:
	$a0 = { 2acd2180fa017402eb1dfab40299b90001cd26eb00b003b90007ba00008e9d99008b5d55e8e3ff }


condition:
	$a0
}