rule Win_Trojan_Trivial_67
{
strings:
	$a0 = { d8c40604002ea362012e8c0664010e0e1f07b80125ba5b012ecd21b41aba8000cd21b44eb90700ba5c01cd2173 }


condition:
	$a0
}