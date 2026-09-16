rule Win_Trojan_Crypt_340
{
strings:
	$a0 = { 558bec81ec80010000c785bcfeffff00000000c785e4feffff00000000c785b4feffff64000000c785e0feffff0c000000c745f0 }


condition:
	$a0
}