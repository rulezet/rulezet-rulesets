rule Win_Trojan_Liberty_1
{
strings:
	$a0 = { 74031f595b505351521e061e0e1fe8 }


condition:
	$a0
}