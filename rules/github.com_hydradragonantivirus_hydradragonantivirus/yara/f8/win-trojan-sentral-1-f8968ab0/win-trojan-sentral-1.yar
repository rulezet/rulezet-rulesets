rule Win_Trojan_Sentral_1
{
strings:
	$a0 = { 20627920546865726d6f4269742f496b582c79324b5d }


condition:
	$a0
}