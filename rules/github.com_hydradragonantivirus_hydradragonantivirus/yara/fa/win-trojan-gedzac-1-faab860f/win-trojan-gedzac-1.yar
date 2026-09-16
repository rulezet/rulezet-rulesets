rule Win_Trojan_Gedzac_1
{
strings:
	$a0 = { 43616c6c58696f004578656358696f004c616e7a617258696f }

	$a1 = { 433a5c78696f2e657865 }


condition:
	$a0 and $a1
}