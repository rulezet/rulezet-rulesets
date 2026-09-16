rule Win_Trojan_VCC_4
{
strings:
	$a0 = { 40b904008d96c500cd21fe86c900b802422bc999cd21b440b926018d960600cd21b43ecd21c3 }


condition:
	$a0
}