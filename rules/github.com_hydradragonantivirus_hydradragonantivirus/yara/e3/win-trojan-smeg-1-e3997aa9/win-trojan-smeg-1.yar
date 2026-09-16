rule Win_Trojan_SMEG_1
{
strings:
	$a0 = { e2585678f4205cdb567eef3842c40c48575f74a2115a10b98a }


condition:
	$a0
}