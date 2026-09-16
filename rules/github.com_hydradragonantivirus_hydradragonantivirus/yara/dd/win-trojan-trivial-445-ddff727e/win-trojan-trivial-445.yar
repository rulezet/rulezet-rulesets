rule Win_Trojan_Trivial_445
{
strings:
	$a0 = { 01b44eb92000cd217220ba9e00b8013dcd218bd8b440b95700ba0001cd21720ab43ecd21b44fcd21 }


condition:
	$a0
}