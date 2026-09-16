rule Win_Trojan_BOO_15
{
strings:
	$a0 = { a3c47cc1e0062d1a00a3be7c2dc307b9be01fc5007f3a4be4c00a5c744fe357dff0e1304a589 }


condition:
	$a0
}