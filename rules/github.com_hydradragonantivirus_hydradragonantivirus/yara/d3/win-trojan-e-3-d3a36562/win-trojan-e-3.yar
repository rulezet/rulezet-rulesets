rule Win_Trojan_E_3
{
strings:
	$a0 = { 8b57028ec38edbbe4c00bff001adab894502adab894502beb207ad8b2c3bc27306adad3bc27206896dfc8945fe83 }


condition:
	$a0
}