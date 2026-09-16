rule Win_Trojan_Tajfun_1
{
strings:
	$a0 = { a327012ea32f01595a83e2f05b32c0b442cd217303eb5090b95102ba0001b440cd217303eb4190 }


condition:
	$a0
}