rule Win_Trojan_VM_1
{
strings:
	$a0 = { 934223c0cf4f16c6ced34003d04d16f01c77d40eefdc7497cfc01b72f177800eefb0cd2a5ac374ddceddc8dc76c1f30e }


condition:
	$a0
}