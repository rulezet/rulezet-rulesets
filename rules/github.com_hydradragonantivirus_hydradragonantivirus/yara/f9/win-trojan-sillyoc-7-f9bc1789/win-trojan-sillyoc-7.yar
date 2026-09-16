rule Win_Trojan_SillyOC_7
{
strings:
	$a0 = { 01b44eb90100cd217302eb0ee80d00ba8000b44fcd217202ebf2cd20ba9e00b80043cd21890e790133c9b80143cd }


condition:
	$a0
}