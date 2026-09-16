rule Win_Trojan_Gotcha_2
{
strings:
	$a0 = { 3ddada742880fc3d740a3d006c7405 }


condition:
	$a0
}