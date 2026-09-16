rule Win_Trojan_Trivial_12
{
strings:
	$a0 = { ba9e00cd21b80143b100cd21b43dcd2193b440b132ba0001cd21b43ecd21b44febd72a2e2a00 }


condition:
	$a0
}