rule Win_Trojan_Trivial_476
{
strings:
	$a0 = { ba1f01b45b33c9cd21721250b92c00ba00018bd8b440cd215bb43ecd21cd20 }


condition:
	$a0
}