rule Win_Trojan_Intrep_2
{
strings:
	$a0 = { 8b055f3b8572017402f8c3f9c3e843007203e990fd }


condition:
	$a0
}