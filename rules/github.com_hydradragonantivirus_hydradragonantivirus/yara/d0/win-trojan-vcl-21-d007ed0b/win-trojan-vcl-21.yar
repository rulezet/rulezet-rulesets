rule Win_Trojan_VCL_21
{
strings:
	$a0 = { 1a8d5680cd21b44eb927005acd217209e814007304b44f }


condition:
	$a0
}