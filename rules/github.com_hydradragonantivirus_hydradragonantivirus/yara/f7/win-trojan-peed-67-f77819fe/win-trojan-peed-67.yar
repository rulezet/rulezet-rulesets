rule Win_Trojan_Peed_67
{
strings:
	$a0 = { b900000000e834000000eb525589e58b55088b02 }


condition:
	$a0
}