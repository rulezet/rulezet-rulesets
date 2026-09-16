rule Win_Trojan_Grog_22
{
strings:
	$a0 = { 1feb16908bf48b34b919030e1f800412802c26e201c3 }


condition:
	$a0
}