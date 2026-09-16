rule Win_Trojan_Wed_2
{
strings:
	$a0 = { 0200e83b00b440b904008bd6cd21b8024233d233c9cd21b440b9290333d2cd21b43ecd21 }


condition:
	$a0
}