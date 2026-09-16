rule Win_Trojan_Empire_5
{
strings:
	$a0 = { 40b904008d96af03cd21fe86b303b802422bc999cd21b440b915048d960600cd21b43ecd21c3 }


condition:
	$a0
}