rule Win_Trojan_Howard_3
{
strings:
	$a0 = { e988a6c701b440b993018d960b01cd217214b8004233c933d2cd21b440b904008d96c701cd21b4 }


condition:
	$a0
}