rule Win_Trojan_Small_4509
{
strings:
	$a0 = { b8751c0506352564450650e81d000000e82f000000565903018d7604 }


condition:
	$a0
}