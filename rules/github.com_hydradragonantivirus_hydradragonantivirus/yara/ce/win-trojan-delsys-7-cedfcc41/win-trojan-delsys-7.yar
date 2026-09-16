rule Win_Trojan_Delsys_7
{
strings:
	$a0 = { 64656c202577696e646972255c636f6d6d616e642e636f6d[0-12]616e642e2a }


condition:
	$a0
}