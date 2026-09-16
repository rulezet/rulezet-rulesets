rule Win_Trojan_Ascii_122_200_245_247_1
{
strings:
	$a0 = { 3132322e3230302e3234352e323437 }


condition:
	$a0
}