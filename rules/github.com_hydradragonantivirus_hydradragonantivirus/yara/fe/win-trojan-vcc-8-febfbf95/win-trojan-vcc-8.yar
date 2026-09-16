rule Win_Trojan_VCC_8
{
strings:
	$a0 = { 40b904008d96de01cd213efe86e201b802422bc999cd21b440b94d018d960601cd21b43ecd21 }


condition:
	$a0
}