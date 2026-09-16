rule Win_Trojan_Philis_106
{
strings:
	$a0 = { 9d08157ead2435d2cf2d363878819ec6c43b65f28979f85d4a3978c7 }


condition:
	$a0
}