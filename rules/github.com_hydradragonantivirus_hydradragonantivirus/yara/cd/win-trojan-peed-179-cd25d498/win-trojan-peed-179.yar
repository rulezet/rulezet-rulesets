rule Win_Trojan_Peed_179
{
strings:
	$a0 = { 8d0567451300ba75e42d0089c1710f5589e587022b55082b550cc9c208007601 }


condition:
	$a0
}