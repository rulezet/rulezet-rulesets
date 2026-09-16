rule Win_Trojan_VCC_6
{
strings:
	$a0 = { b904008d96da00cd21fe86de00b802422bc999cd21b440b945018d960600cd21b43ecd21c3 }


condition:
	$a0
}