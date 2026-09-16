rule Win_Trojan_VB_1570
{
strings:
	$a0 = { 2b020000b62b00001f1d000044004603ff0125000000010a006469706c6f }


condition:
	$a0
}