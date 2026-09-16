rule Win_Trojan_Baba_2
{
strings:
	$a0 = { 0181c64601b90400fcf3a45eb8babacd213dccfa7503 }


condition:
	$a0
}