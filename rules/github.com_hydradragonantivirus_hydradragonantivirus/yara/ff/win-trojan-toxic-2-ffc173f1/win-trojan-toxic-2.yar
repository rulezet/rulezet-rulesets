rule Win_Trojan_Toxic_2
{
strings:
	$a0 = { bf000157a5a4b41abae301cd21badd01b44eb90700cd217229b000e8a400b43fba0e02b91a00cd21b43ecd21a1 }


condition:
	$a0
}