rule Win_Trojan_Trojan_239
{
strings:
	$a0 = { 030089869d0332c0e82801b440b903008d969c03cd21b002e81801b440b99a028d960301cd21 }


condition:
	$a0
}