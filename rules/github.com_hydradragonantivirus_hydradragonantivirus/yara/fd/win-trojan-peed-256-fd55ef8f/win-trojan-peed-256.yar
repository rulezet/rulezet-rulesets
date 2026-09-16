rule Win_Trojan_Peed_256
{
strings:
	$a0 = { e85000000068a4b000005981c1508d000081c1a4b0000068ae }


condition:
	$a0
}