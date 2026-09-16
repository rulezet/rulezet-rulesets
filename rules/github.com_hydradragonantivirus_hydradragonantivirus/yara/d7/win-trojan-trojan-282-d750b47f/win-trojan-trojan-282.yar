rule Win_Trojan_Trojan_282
{
strings:
	$a0 = { ba1a01b44ecd21ba9e00b8013dcd218bd8b440b11eba0001cd21 }


condition:
	$a0
}