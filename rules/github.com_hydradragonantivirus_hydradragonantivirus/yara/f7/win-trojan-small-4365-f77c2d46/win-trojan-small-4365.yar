rule Win_Trojan_Small_4365
{
strings:
	$a0 = { b808010070e9??0000005050 }


condition:
	$a0
}