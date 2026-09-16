rule Win_Trojan_Sality_1045
{
strings:
	$a0 = { 5f83c7018a440500300780e9015e4e0f84??000000 }


condition:
	$a0
}