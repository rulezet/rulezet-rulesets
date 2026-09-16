rule Win_Trojan_Peed_39
{
strings:
	$a0 = { b9f832230f4001c2e2fb85db74f7b908 }


condition:
	$a0
}