rule Win_Trojan_Trivial_382
{
strings:
	$a0 = { b44eb90200ba4c01cd21ba4c0133c9b8023ccd2193b440b95f00ba0001cd2151b439ba5201 }


condition:
	$a0
}