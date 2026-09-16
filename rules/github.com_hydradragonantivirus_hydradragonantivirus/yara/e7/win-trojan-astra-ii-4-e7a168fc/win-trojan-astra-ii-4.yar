rule Win_Trojan_Astra_II_4
{
strings:
	$a0 = { 8ec0be790003f58bfeb96f018bddfcad33876700abe2f8 }


condition:
	$a0
}