rule Win_Trojan_Lineage_97
{
strings:
	$a0 = { 04ba2d89fd6a9656a2cd1d14d9fdea07d090b18cb559164b67299387e9b58af4f0322f026535c8eb8d2d7b4e91b51070ab27d980526e47104e8e9defe284ee0471b32dc5 }


condition:
	$a0
}