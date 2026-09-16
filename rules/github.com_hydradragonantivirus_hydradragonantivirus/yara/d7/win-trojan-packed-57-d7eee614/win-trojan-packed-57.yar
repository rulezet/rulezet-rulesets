rule Win_Trojan_Packed_57
{
strings:
	$a0 = { 9c607061636b244033c0619d60e80000000090 }


condition:
	$a0
}