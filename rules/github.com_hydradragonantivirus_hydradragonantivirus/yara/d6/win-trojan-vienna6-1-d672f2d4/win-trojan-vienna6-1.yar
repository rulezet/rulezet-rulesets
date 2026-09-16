rule Win_Trojan_Vienna6_1
{
strings:
	$a0 = { 8e1e2c00ac3c3b74093c007403aaebf4 }


condition:
	$a0
}