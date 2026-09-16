rule Win_Trojan_Trivial_499
{
strings:
	$a0 = { 2189deb8014333c98d541ecd21b8023dcd2193 }


condition:
	$a0
}