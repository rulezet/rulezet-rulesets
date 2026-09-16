rule Win_Trojan_Empire_6
{
strings:
	$a0 = { b80040b904008d961201cd21fe861601b802422bc999cd21b440b978018d960600cd21b43ecd21c3 }


condition:
	$a0
}