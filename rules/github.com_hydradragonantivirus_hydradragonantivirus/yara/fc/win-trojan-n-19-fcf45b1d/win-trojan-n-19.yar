rule Win_Trojan_N_19
{
strings:
	$a0 = { ed3f111e3b50d7e98d0ce9b4c39a23f68e0e95c1def7079a3c0d8a7c8a1d077e8a }


condition:
	$a0
}