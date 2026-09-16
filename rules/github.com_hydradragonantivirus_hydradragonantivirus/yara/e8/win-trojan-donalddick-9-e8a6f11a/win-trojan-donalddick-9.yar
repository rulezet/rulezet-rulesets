rule Win_Trojan_DonaldDick_9
{
strings:
	$a0 = { 2e518bcb5088d6c1e20888f2c1e20888f2e8 }

	$a1 = { 6f6c6570726f632e[0-34]626f6f74657865632e }


condition:
	$a0 and $a1
}