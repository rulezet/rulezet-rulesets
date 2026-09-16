rule Win_Trojan_Trivial_261
{
strings:
	$a0 = { 8bd8b440cd21b43ecd21cd202a2e636f6d00 }


condition:
	$a0
}