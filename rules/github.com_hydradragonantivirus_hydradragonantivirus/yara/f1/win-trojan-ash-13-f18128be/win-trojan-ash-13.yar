rule Win_Trojan_Ash_13
{
strings:
	$a0 = { 1f02c6862002deb442b00033c933d2cd21b440b904008d961d02cd21b442b00233c933d2cd }


condition:
	$a0
}