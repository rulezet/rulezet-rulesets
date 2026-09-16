rule Win_Trojan_VCL_23
{
strings:
	$a0 = { 5680cd21b44eb927005acd217209e80f007304b44f }


condition:
	$a0
}