rule Win_Trojan_Peed_332
{
strings:
	$a0 = { e80200000087f75eb9fe960100ba04040040c1c20c89d652ad05 }


condition:
	$a0
}