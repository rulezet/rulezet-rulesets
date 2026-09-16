rule Win_Trojan_AusTerm_1
{
strings:
	$a0 = { fae800005b8beb8bf4bc3510b97b0d81c518002e316600d1c445e2f7 }


condition:
	$a0
}