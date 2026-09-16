rule Win_Trojan_Guppy_3
{
strings:
	$a0 = { b8023dcd2193e800005e0e1fb43f }


condition:
	$a0
}