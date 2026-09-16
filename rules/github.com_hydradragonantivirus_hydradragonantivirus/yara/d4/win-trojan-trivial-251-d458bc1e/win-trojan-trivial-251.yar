rule Win_Trojan_Trivial_251
{
strings:
	$a0 = { b92000b44ecd217217ba9e00b43db001cd21720c8bd8b440b92b00ba0001cd21cd202a2e636f6d00 }


condition:
	$a0
}