rule Win_Trojan_Kornik_1
{
strings:
	$a0 = { 1801eb0a34c62947eb054b2813803e3074ce4f0000d76578650450415448013b9a804d00 }


condition:
	$a0
}