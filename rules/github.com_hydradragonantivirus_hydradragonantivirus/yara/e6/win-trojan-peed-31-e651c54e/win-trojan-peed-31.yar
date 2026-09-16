rule Win_Trojan_Peed_31
{
strings:
	$a0 = { 6a00e871feffffc3558d6c248c81ec140100008d45e050c745e094000000ff15 }


condition:
	$a0
}