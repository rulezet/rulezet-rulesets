rule Win_Trojan_Gerli_2
{
strings:
	$a0 = { 022e8db60f0189f78a260a03ac2e33865403aae2f7c3 }


condition:
	$a0
}