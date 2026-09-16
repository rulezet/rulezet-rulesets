rule Win_Trojan_W_228
{
strings:
	$a0 = { 7465726e697479ff6f6e6f0e2d4330002d00ffcc310000f8c307e0d5086fffffffff45aa0444f3f692d94ba38135b845 }


condition:
	$a0
}