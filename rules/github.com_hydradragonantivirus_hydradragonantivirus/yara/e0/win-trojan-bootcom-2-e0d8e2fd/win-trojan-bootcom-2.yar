rule Win_Trojan_BootCOM_2
{
strings:
	$a0 = { 33c08ed8bb2a01be007c56ff0e1304a11304c1e0062d10 }


condition:
	$a0
}