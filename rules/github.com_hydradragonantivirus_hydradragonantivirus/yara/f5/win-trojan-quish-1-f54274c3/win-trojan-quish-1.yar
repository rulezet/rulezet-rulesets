rule Win_Trojan_Quish_1
{
strings:
	$a0 = { 1f02b440b904008d962502cd21b8024233c933d2cd21b440b92f018d960001cd21b8002ccd21 }


condition:
	$a0
}