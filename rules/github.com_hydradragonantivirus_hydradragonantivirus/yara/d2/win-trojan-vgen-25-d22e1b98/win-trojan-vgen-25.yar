rule Win_Trojan_VGEN_25
{
strings:
	$a0 = { e800005e0e1f81ee43008bfe83e7f08bc7b104d3e88cc903c150b8650050b9630bfcf3a4cb0e1fbe060033ff2e803e06 }


condition:
	$a0
}