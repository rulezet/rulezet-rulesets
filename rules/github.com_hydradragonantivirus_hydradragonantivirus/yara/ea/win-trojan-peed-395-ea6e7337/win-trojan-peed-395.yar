rule Win_Trojan_Peed_395
{
strings:
	$a0 = { 6bc900e834000000f7d029c74f4029c6eb4a5589e5ad83ee04c9c2080089daf7 }


condition:
	$a0
}