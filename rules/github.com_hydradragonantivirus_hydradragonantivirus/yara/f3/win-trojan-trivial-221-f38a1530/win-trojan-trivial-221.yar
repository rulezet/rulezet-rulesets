rule Win_Trojan_Trivial_221
{
strings:
	$a0 = { ba0c01b120cd217307c32a2e434f4d0086f0b43db29ecd2193b440ba0001b128cd21b44febda }


condition:
	$a0
}