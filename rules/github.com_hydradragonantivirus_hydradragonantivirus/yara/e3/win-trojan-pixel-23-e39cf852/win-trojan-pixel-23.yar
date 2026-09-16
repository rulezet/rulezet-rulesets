rule Win_Trojan_Pixel_23
{
strings:
	$a0 = { 01b41acd21ba0401b90600b44ecd217303e9c200ba3701b443b001b92000cd21b8023dcd218b }


condition:
	$a0
}