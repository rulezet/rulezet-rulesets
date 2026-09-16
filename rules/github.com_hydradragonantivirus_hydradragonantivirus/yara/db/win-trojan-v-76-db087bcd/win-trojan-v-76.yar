rule Win_Trojan_V_76
{
strings:
	$a0 = { 33d2b440cd218b160c008b0e0e0081c22e0083d100 }


condition:
	$a0
}