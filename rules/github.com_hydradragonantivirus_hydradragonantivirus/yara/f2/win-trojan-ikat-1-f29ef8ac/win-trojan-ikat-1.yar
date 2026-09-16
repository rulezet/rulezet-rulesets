rule Win_Trojan_Ikat_1
{
strings:
	$a0 = { 558bec83c4f0535633c08945f0b83cfc4300e80d00525033c0556877fe430064ff30648920e80d0018f0b8c0 }


condition:
	$a0
}