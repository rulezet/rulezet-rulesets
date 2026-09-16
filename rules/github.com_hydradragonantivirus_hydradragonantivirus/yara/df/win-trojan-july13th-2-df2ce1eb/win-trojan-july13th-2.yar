rule Win_Trojan_July13th_2
{
strings:
	$a0 = { 12003490be1200b9b1042e300446e2fa }


condition:
	$a0
}