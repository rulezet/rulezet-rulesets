rule Win_Trojan_Pixel_21
{
strings:
	$a0 = { b90600b44ecd21724bba2f01b802 }


condition:
	$a0
}