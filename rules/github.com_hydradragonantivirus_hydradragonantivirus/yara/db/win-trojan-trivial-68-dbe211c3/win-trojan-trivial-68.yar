rule Win_Trojan_Trivial_68
{
strings:
	$a0 = { 01b90000cd218bd8ba0001b98e00b440cd21b44eb120ba4701cd21b8013dba9e00cd218b }


condition:
	$a0
}