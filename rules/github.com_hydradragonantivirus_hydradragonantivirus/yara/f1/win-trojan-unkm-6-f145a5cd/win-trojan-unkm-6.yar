rule Win_Trojan_Unkm_6
{
strings:
	$a0 = { 968000b41acd21b44eb906008d96ca02cd217215e81d007410b43ecd21b8004fcd217205e80d00 }


condition:
	$a0
}