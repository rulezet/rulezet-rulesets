rule Win_Trojan_C_78
{
strings:
	$a0 = { ffb7eb2ab87af2e8b1fe590bc075ffff16833e7803007c0f7f08813e76032413711a7605e3 }


condition:
	$a0
}