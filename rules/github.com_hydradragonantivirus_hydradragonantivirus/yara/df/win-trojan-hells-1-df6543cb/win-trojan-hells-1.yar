rule Win_Trojan_Hells_1
{
strings:
	$a0 = { 496e6665637420627920537074682e323031002a2e636f6d }


condition:
	$a0
}