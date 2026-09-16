rule Win_Trojan_Trivial_183
{
strings:
	$a0 = { 2a2e652ab44e8bd6cd21b82e5bba9e00f2ae66c705434f4d008bcecd2193b44073e4c3 }


condition:
	$a0
}