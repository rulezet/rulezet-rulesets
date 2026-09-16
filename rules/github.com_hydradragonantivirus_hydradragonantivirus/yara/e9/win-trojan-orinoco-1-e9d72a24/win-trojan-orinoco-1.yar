rule Win_Trojan_Orinoco_1
{
strings:
	$a0 = { 33d2b23f2622550580fa017316b80102b90100bb1b0a0e07cd13720ab80103cd137203f8eb01f9 }


condition:
	$a0
}