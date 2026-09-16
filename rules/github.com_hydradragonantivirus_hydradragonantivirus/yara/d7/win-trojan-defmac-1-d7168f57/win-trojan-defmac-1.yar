rule Win_Trojan_Defmac_1
{
strings:
	$a0 = { 687474703a2f2f25402f692e70687025 }

	$a1 = { 2e2f4d616353656375726974792e6170702f }


condition:
	$a0 and $a1
}