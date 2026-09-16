rule Win_Trojan_JT8_1
{
strings:
	$a0 = { b8014035fffff7d04891909091cd21722433c933d2b8004235fffff7d0cd218d967902b904 }


condition:
	$a0
}