rule Win_Trojan_Vgen_17
{
strings:
	$a0 = { 89864bb9fd04fc46bf4701902bda310d33d12bd8310547424b4090e2ee4b4b42474342f847ff187118d2a54019e2 }


condition:
	$a0
}