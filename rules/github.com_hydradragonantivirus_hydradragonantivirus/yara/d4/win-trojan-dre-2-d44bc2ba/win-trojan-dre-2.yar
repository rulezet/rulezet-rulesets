rule Win_Trojan_Dre_2
{
strings:
	$a0 = { 1fb41a8d160301cd21b44eb900008d162e01cd217309c3b8004fcd217301c38d162101b90000b80143cd21b8023dba }


condition:
	$a0
}