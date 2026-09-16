rule Win_Trojan_Nado_3
{
strings:
	$a0 = { 420289164e02a35002050000a34802c7064a020000b440b95802ba0000cd210e1fb80242e84b }


condition:
	$a0
}