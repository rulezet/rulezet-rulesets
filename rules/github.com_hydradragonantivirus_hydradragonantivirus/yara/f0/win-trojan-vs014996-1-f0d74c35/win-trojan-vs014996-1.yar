rule Win_Trojan_VS014996_1
{
strings:
	$a0 = { 5d83ed3587f7555e83c615a5a52e9c589e7309b81010e770b0fee664fab0aee664eb00fbe8 }


condition:
	$a0
}