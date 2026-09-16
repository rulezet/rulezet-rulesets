rule Win_Trojan_C_51
{
strings:
	$a0 = { 7865000080000091b7108bd38a269201cd218a269301cd218a269401bf1e108bd6cd217328 }


condition:
	$a0
}