rule Win_Trojan_Cruel_2
{
strings:
	$a0 = { 33c08ed0bc007cfb8ec0b80202bb007eb90400b601b200cd130653cb }


condition:
	$a0
}