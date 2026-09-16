rule Win_Trojan_W_382
{
strings:
	$a0 = { 30750c81f96719750681fb917674069d2eff2e }


condition:
	$a0
}