rule Win_Trojan_Swapper_1
{
strings:
	$a0 = { e800005d8d76fcbf00f0b97501f3a56814f0c3 }


condition:
	$a0
}