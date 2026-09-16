rule Win_Trojan_Trivial_463
{
strings:
	$a0 = { b44eb90000ba3601cd21721fb43db002ba9e00cd2193b440b93c00ba0001cd21b43ecd21 }


condition:
	$a0
}