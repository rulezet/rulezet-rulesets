rule Win_Trojan_Dobki_2
{
strings:
	$a0 = { 25ba0d01eb01e8cd21eb06c606190143cfccc6061a0140909080fb0174060ac07402cd20b1bfbe44018bfe803ebe }


condition:
	$a0
}