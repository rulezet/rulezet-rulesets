rule Win_Trojan_Whale_8
{
strings:
	$a0 = { 50e82a0081c260dcb511b1c387dae8df }


condition:
	$a0
}