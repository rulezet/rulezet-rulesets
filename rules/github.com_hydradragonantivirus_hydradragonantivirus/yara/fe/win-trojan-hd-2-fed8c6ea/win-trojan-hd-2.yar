rule Win_Trojan_HD_2
{
strings:
	$a0 = { b200b600b500b101b008cd13b400cd21 }


condition:
	$a0
}