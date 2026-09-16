rule Win_Trojan_AntiPas_2
{
strings:
	$a0 = { e800005e81ee6501888454018b840601 }


condition:
	$a0
}