rule Win_Trojan_Mataj13_1
{
strings:
	$a0 = { ba1d01b409cd21baf101b41acd21b44e }


condition:
	$a0
}