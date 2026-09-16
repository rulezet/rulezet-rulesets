rule Win_Trojan_W_263
{
strings:
	$a0 = { 8d4424f833db648703e8000000005b8d4b4f9090905150500f014c24fe5b83c31cfa8b2b668b6b }


condition:
	$a0
}