rule Win_Trojan_Nomenclature_1
{
strings:
	$a0 = { aa4bcd2173785e560633c08ed8c41e }


condition:
	$a0
}