rule Win_Trojan_Victor_1
{
strings:
	$a0 = { 8cc88bd8b104d3ee03c650b8d80050cb }


condition:
	$a0
}