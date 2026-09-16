rule Win_Trojan_W_261
{
strings:
	$a0 = { 8d4424f833db648703e8000000005b8d4b519090905150500f014c24fe5b83c334fa8b2b668b6b }


condition:
	$a0
}