rule Win_Trojan_Chance_2
{
strings:
	$a0 = { 03836f23028b4723b106d3e050be007c8ec033ffb90001fcf3a5b86a0050cb2eff06f7012e8a }


condition:
	$a0
}