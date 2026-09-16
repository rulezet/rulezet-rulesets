rule Win_Trojan_Surrender_1
{
strings:
	$a0 = { b80043cc51b8014333c9ccb8023dcc0e1f8bd8b43fb1 }


condition:
	$a0
}