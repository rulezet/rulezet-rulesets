rule Win_Trojan_Peed_82
{
strings:
	$a0 = { 558bec83ec0c535657e842feffffe8deffffff8d4df8 }


condition:
	$a0
}