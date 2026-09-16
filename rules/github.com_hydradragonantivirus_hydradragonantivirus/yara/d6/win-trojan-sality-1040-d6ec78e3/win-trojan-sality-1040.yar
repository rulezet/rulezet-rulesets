rule Win_Trojan_Sality_1040
{
strings:
	$a0 = { 02c5[0-1]5f83c7018a440500300780e9015e4e0f85??ffffff }


condition:
	$a0
}