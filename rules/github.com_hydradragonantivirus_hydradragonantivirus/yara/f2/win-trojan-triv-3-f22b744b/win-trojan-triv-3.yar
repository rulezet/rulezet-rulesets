rule Win_Trojan_Triv_3
{
strings:
	$a0 = { b44eba0e01cd21b43cba9e00cd212a2e2a00b74087d193eb }


condition:
	$a0
}