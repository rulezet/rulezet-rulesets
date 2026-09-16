rule Win_Trojan_Trivial_186
{
strings:
	$a0 = { 01b440cd21b43ecd21cd202a2e2a00 }


condition:
	$a0
}