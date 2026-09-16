rule Win_Trojan_Tiny_56
{
strings:
	$a0 = { 4b75711e0652575150531e078bfab90001b02ef2ae80 }


condition:
	$a0
}