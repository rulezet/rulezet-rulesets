rule Win_Trojan_Elfish_1
{
strings:
	$a0 = { 558bec83c4f0b85c524000e8ecf1ffffe8aff7ffff68e05240006a00[0-48]656c66697368 }


condition:
	$a0
}