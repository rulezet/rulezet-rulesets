rule Win_Trojan_Crypt_272
{
strings:
	$a0 = { 6e5c52756e5d0d0a224d7950726f6772616d223d22496e7374616c6c2e657865 }


condition:
	$a0
}