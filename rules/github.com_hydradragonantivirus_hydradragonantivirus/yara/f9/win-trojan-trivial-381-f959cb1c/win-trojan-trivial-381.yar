rule Win_Trojan_Trivial_381
{
strings:
	$a0 = { 3fcd21803ce9741bb002e81b0097b15bb440cd21b000e80f00c604e9897c01b440cd21b43ecd21 }


condition:
	$a0
}