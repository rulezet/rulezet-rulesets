rule Win_Trojan_Funeral_1
{
strings:
	$a0 = { 1e44038c064603b81c25ba4c03cd21 }


condition:
	$a0
}