rule Win_Trojan_AntiPas_1
{
strings:
	$a0 = { b801908d940601b440cd21722258055200c605e9894501 }


condition:
	$a0
}