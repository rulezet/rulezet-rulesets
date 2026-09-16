rule Win_Trojan_Gigi_3
{
strings:
	$a0 = { be0001b9100033d2ac32e403d08ad8f6e303d0e2f381fa }


condition:
	$a0
}