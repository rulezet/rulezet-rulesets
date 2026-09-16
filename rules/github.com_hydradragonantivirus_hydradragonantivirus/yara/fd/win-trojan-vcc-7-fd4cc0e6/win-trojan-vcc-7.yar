rule Win_Trojan_VCC_7
{
strings:
	$a0 = { b80040b904008d96dd01cd213efe86e101b802422bc999cd21b440b94c018d960601cd21b43ecd21 }


condition:
	$a0
}