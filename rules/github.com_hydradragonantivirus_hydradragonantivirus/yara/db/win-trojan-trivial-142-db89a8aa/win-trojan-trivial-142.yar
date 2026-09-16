rule Win_Trojan_Trivial_142
{
strings:
	$a0 = { 4f2a008bd6b44ecd21ba9e00b8013dcd21938bd6b11eb440cd21c3 }


condition:
	$a0
}