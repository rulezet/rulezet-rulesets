rule Win_Trojan_Erasmus_1
{
strings:
	$a0 = { cd13b405b501b101b600b203cd13 }


condition:
	$a0
}