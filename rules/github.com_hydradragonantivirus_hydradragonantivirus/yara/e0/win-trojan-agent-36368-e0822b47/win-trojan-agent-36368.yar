rule Win_Trojan_Agent_36368
{
strings:
	$a0 = { 8b0e83c20889088b4e048948048a0d??????0083c00883c70883c60842880883ed084083fd087fd8 }


condition:
	$a0
}