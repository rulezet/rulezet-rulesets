rule Win_Trojan_Trivial_100
{
strings:
	$a0 = { 4eba0e00cd21b43cba9e00cd212a2e2a00b74087d193ebf3 }


condition:
	$a0
}