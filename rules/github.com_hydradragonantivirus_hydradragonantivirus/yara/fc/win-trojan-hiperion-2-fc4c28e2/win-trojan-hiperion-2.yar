rule Win_Trojan_Hiperion_2
{
strings:
	$a0 = { 80fc4b75115351561e525533ede80d005d5a1f5e595b }


condition:
	$a0
}