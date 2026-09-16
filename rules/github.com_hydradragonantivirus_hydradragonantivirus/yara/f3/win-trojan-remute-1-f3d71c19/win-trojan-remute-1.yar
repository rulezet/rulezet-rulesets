rule Win_Trojan_Remute_1
{
strings:
	$a0 = { 4e4e4eb452cd21268b7f0426c47dfc4f26817dfe8ae175f7065733c08ec0268f065c03268f065e0356f8b8f1e0cd21 }


condition:
	$a0
}