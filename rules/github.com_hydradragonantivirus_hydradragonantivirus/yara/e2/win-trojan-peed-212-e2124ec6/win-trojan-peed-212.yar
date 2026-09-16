rule Win_Trojan_Peed_212
{
strings:
	$a0 = { ba73e4ff00f889c1712281e91132ab006800 }


condition:
	$a0
}