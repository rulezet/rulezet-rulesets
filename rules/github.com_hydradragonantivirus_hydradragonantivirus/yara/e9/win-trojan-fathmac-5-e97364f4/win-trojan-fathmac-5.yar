rule Win_Trojan_FathMac_5
{
strings:
	$a0 = { 01b9ff0681e91a0105000080c40088f6268a0288f6346483eb0026880280ef0080c70046e2e5 }


condition:
	$a0
}