rule Win_Trojan_Bancos_877
{
strings:
	$a0 = { ae63d41a1bc9cbb9d015b620eac082e3ede11fe61ab7f1281f743ae0fced093bd290028a1a2b5965900b99d9c65ed8ae533998e2ff7bbacd3c5227611ce5e5f802 }


condition:
	$a0
}