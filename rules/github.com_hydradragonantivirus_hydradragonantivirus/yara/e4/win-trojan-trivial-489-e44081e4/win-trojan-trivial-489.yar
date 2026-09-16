rule Win_Trojan_Trivial_489
{
strings:
	$a0 = { 01cd21cd20b44eb90000ba4201cd21b43db002ba9e00cd2193b440b97300ba0001cd21b43ecd }


condition:
	$a0
}