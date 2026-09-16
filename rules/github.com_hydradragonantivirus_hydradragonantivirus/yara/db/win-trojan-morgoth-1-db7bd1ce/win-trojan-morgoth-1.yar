rule Win_Trojan_Morgoth_1
{
strings:
	$a0 = { 33c933d2cd21b440b904008d968e01cd21b43ecd21b44feb9eba8000b41acd21b8000150c3 }


condition:
	$a0
}