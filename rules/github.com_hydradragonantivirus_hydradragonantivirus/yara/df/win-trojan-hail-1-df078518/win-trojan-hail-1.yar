rule Win_Trojan_Hail_1
{
strings:
	$a0 = { b90200be9a008dbe6300f3a42eff8663002e8b8663003d00fa7733b440b904008d966200cd21 }


condition:
	$a0
}