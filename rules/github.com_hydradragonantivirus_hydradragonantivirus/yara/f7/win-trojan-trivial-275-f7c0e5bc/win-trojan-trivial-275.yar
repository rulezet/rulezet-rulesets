rule Win_Trojan_Trivial_275
{
strings:
	$a0 = { 01b44ecd217217ba9e00b8013dcd2193b440b92d00ba0001cd21b43ecd21b409ba2f01cd21cd }


condition:
	$a0
}