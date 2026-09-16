rule Win_Trojan_Peed_203
{
strings:
	$a0 = { 73255589e551418b7d0c66abc1c81066ab83ef0283ef02e2ee59f75d }


condition:
	$a0
}