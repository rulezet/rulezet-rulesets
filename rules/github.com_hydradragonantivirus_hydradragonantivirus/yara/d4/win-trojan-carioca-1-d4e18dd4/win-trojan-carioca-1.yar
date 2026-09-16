rule Win_Trojan_Carioca_1
{
strings:
	$a0 = { 01fcf3a4b8000150c32e8b1e030181c3 }


condition:
	$a0
}