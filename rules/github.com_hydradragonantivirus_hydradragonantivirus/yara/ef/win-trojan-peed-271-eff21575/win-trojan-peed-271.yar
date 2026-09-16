rule Win_Trojan_Peed_271
{
strings:
	$a0 = { fdbd67453200fc89e673418f05adfa7b00f7d36845230100ff1522e47f00e83e }


condition:
	$a0
}