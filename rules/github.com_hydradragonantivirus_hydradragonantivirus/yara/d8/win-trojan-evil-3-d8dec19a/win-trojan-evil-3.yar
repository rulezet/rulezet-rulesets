rule Win_Trojan_Evil_3
{
strings:
	$a0 = { 95bf000147033d8bf733c0ba40035233 }


condition:
	$a0
}