rule Win_Trojan_Trivial_244
{
strings:
	$a0 = { b44ecd21ba9e00b8013dcd2193b440b12aba0001cd21b43ecd21b44fcd2173e4c3 }


condition:
	$a0
}