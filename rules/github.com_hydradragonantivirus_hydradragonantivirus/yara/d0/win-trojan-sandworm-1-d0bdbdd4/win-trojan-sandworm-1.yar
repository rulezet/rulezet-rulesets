rule Win_Trojan_Sandworm_1
{
strings:
	$a0 = { c3bf2f0303fe8aa41203b9dc058ad480e20ff8302502e247e2f9eb0100b8ebebcd1c3d34127503e98100b800008e }


condition:
	$a0
}