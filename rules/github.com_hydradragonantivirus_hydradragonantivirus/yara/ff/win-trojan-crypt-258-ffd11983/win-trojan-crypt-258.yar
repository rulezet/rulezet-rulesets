rule Win_Trojan_Crypt_258
{
strings:
	$a0 = { 09c8390d40da8a1374112bc1b84d }

	$a1 = { 494a4b4c2f3a324d324e4f36423d3d }

	$a2 = { 77676171bf4f6e5be76f5767e6766e6f75 }


condition:
	$a0 and $a1 and $a2
}