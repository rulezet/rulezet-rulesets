rule Win_Trojan_Gen_198
{
strings:
	$a0 = { 7512c55f01813f909075f283eb32813f9090743a813f1e2e750983c325813ffa80742b09c0 }


condition:
	$a0
}