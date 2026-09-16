rule Win_Trojan_Phonix_1
{
strings:
	$a0 = { 33d2520726803eff04ff7501c3e800005e2e80bc4403ff74 }


condition:
	$a0
}