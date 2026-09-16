rule Win_Trojan_DeltreeY_29
{
strings:
	$a0 = { 44454c545245450015202f7920433a5c77696e646f77735c2a2e657865 }


condition:
	$a0
}