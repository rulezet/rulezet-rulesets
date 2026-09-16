rule Win_Trojan_Stryke_1
{
strings:
	$a0 = { bafe00cd2172ae58fec4c1e804a3f100b440ba0000b9fe00cd21729932c0e80e007292b440ba }


condition:
	$a0
}