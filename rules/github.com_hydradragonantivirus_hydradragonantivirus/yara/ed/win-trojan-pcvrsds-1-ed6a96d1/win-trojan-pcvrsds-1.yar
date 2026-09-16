rule Win_Trojan_PcVrsDs_1
{
strings:
	$a0 = { be1c00b94f072e8a9708002e0010 }


condition:
	$a0
}