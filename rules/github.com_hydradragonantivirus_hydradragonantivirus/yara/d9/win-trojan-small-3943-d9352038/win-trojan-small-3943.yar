rule Win_Trojan_Small_3943
{
strings:
	$a0 = { 558bec6a00535657bbe4a74000bea8924000bfe8a7400033c05568dc86400064ff30648920e8a2fdffff8bc38b15a4924000e82db2ffff8d55fc8b03e877d2ffffeb3e }


condition:
	$a0
}