rule Win_Trojan_Small_4302
{
strings:
	$a0 = { e83d000000e8630000008d2d2e974705e86400000089c2ad81f70000000081f0 }


condition:
	$a0
}