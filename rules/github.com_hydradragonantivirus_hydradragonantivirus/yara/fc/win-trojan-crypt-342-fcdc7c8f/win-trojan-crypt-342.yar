rule Win_Trojan_Crypt_342
{
strings:
	$a0 = { 558bec81ec84010000c785bcfeffff00000000c785e4feffff00000000c785b4feffff64000000c785e0feffff0a }


condition:
	$a0
}