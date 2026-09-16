rule Win_Trojan_Trivial_180
{
strings:
	$a0 = { ba1e01cd21ba9e00b8023dcd2193ba0001b440b123cd21b43ecd21c3 }


condition:
	$a0
}