rule Win_Trojan_Agent_35789
{
strings:
	$a0 = { 68fe0f16d9e80164000000004f666673657452656374 }


condition:
	$a0
}