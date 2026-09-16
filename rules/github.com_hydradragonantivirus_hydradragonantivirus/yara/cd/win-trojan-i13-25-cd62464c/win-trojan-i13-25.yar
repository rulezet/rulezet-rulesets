rule Win_Trojan_I13_25
{
strings:
	$a0 = { b41b06067f120a0469c9930e7270b1ed77040a177fc993397f17c7075bbcb2020a2587c9932a3b9a }


condition:
	$a0
}