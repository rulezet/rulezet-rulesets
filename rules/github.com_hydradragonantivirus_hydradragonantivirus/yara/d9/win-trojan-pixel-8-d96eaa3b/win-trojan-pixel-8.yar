rule Win_Trojan_Pixel_8
{
strings:
	$a0 = { b44fba9902cd217202eb97ba8000eb05 }


condition:
	$a0
}