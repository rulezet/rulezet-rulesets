rule Win_Trojan_Forger_1
{
strings:
	$a0 = { 0e1f5f070657b80000b98000f2ae4783f9007503e9 }


condition:
	$a0
}