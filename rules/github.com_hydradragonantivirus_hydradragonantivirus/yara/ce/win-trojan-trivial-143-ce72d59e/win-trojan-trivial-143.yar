rule Win_Trojan_Trivial_143
{
strings:
	$a0 = { b44eba1a01cd21ba9e00b8023dcd2193b11eba0001b440cd21c3 }


condition:
	$a0
}