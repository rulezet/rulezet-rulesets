rule Win_Trojan_VGEN_26
{
strings:
	$a0 = { b800e8cf0072f4e8b0000e07be0714bba202b44acd21565fb8004b87f3af2ea4ae268c0574f7cd210e1fb80069bb03 }


condition:
	$a0
}