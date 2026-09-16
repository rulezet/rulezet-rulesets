rule Win_Trojan_Riot_7
{
strings:
	$a0 = { e800008b2e0001bcfeff81edf605be090603f5c604c3c604c6e8ccffe9f1fa }


condition:
	$a0
}