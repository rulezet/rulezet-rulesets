rule Win_Trojan_Pixel_3
{
strings:
	$a0 = { 250100744cbad801b409cd21cd20 }


condition:
	$a0
}