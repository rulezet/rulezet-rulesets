rule Win_Trojan_Copmpl_2
{
strings:
	$a0 = { 8ad680fa00740780fa0b7606b202b40ecd218cc88e }


condition:
	$a0
}