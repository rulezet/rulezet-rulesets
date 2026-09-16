rule Win_Trojan_Esllactol_1
{
strings:
	$a0 = { ff15??204100ff15??2041008b1d??204100ffd?ffd?ffd?ffd?ffd?ffd?8b1d??204100 }


condition:
	$a0
}