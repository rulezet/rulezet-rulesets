rule Win_Trojan_Trivial_299
{
strings:
	$a0 = { 2d01b44eb90100cd217220ba9e00b8023dcd2172168bd8ba0001b440b93300cd21b43ecd21b44fcd2173e0c3 }


condition:
	$a0
}