rule Win_Trojan_Fakeav_43
{
strings:
	$a0 = { 528f051ff64300578f05c6f7430089357bf643008d3dcaf54300575889188d05 }


condition:
	$a0
}