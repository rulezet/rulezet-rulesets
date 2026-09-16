rule Win_Trojan_Zherkov_4
{
strings:
	$a0 = { e800005e2e8a44ed3c0074238bfe83c72c90b9bf085157bb }


condition:
	$a0
}