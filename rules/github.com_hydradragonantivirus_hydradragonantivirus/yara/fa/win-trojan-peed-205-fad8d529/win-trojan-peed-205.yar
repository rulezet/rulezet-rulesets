rule Win_Trojan_Peed_205
{
strings:
	$a0 = { e8250000005589e551418b7d0c66abc1c81066ab83ef0283ef02e2ee59f75d08 }


condition:
	$a0
}