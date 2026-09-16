rule Win_Trojan_Tiny_68
{
strings:
	$a0 = { 77b33e89862102b440b904008d960401cd21b440b918018d960801cd21b8004233c933d2cd }


condition:
	$a0
}