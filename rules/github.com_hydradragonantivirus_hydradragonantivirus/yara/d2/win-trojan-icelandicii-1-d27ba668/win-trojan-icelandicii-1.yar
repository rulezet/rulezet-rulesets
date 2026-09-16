rule Win_Trojan_IcelandicII_1
{
strings:
	$a0 = { 067902029050535152561e8bda43 }


condition:
	$a0
}