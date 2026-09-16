rule Win_Trojan_Desperado_2
{
strings:
	$a0 = { 080c289c4b590c5be67f0e04097d8e16081bba65c37a3dad8085565cadcb0ed708c90ec651050944 }


condition:
	$a0
}