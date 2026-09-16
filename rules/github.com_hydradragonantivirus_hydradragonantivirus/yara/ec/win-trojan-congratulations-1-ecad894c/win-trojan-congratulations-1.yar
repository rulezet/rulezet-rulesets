rule Win_Trojan_Congratulations_1
{
strings:
	$a0 = { 8a0e17008ac1593490be1700b996032e300446e2fa }


condition:
	$a0
}