rule Win_Trojan_Floriana_1
{
strings:
	$a0 = { be0083c4fe5e81c6fdfe2e81bca704464275ec5033c0501f813e0e0246420e1f753dfc2ef684d90302741f065b5359 }


condition:
	$a0
}