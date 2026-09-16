rule Win_Trojan_Trivial_474
{
strings:
	$a0 = { 010090ba7901e80200cd20b44eb90700cd2172f5ba9e00b80043cd21890e8e01b8014333c9cd21b8023dcd2193 }


condition:
	$a0
}