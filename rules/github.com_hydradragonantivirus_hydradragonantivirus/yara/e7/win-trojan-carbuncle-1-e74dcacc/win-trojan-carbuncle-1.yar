rule Win_Trojan_Carbuncle_1
{
strings:
	$a0 = { 02b90000b43ccd218bd8b96e02ba0001b440cd21b43e }


condition:
	$a0
}