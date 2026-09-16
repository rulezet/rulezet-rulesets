rule Win_Trojan_Trivial_235
{
strings:
	$a0 = { 013dba9e00cd2193b440b12aba0001cd21b43ecd21b44fcd2173e4c3 }


condition:
	$a0
}