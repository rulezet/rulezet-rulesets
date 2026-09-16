rule Win_Trojan_VGEN_646
{
strings:
	$a0 = { e2002ea300018aa4e4002e88260201f8e8b300b44eb903008d94e500cd217232eb06b44fcd21722aba9e00b801 }


condition:
	$a0
}