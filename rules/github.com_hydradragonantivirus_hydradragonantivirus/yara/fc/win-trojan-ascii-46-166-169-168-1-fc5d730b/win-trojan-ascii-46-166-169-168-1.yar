rule Win_Trojan_Ascii_46_166_169_168_1
{
strings:
	$a0 = { 34362e3136362e3136392e313638 }


condition:
	$a0
}