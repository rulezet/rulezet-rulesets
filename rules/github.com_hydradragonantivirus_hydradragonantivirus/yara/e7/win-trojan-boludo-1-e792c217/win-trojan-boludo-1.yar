rule Win_Trojan_Boludo_1
{
strings:
	$a0 = { b92401302446e2fb5ec3e80100cf5d }


condition:
	$a0
}