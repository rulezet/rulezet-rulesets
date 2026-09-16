rule Win_Trojan_Trivial_140
{
strings:
	$a0 = { ba1a01cd21ba9e00b8013dcd2193b44049ba0001cd21c3 }


condition:
	$a0
}