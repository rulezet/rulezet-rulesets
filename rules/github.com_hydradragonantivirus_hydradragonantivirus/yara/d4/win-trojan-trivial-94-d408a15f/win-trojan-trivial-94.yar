rule Win_Trojan_Trivial_94
{
strings:
	$a0 = { 21b43cba9e00cd21b74087d193ebf7 }


condition:
	$a0
}