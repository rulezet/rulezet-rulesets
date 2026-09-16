rule Win_Trojan_Spambot_278
{
strings:
	$a0 = { 558bec83ec14535657837d0c010f858f0200008365f000 }


condition:
	$a0
}