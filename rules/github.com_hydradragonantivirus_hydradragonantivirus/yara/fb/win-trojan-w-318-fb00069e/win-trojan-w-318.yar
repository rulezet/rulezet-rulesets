rule Win_Trojan_W_318
{
strings:
	$a0 = { 33c9b1b46033c0f3ae9cb44299ffd59d61750bf3a4894772b440b510ffd5b43e }


condition:
	$a0
}