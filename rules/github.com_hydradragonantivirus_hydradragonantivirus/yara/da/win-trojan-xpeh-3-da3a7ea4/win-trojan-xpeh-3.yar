rule Win_Trojan_XPEH_3
{
strings:
	$a0 = { baa700b409cd21b03fb90b00bfa812fc }


condition:
	$a0
}