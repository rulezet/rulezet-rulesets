rule Win_Trojan_VGEN_527
{
strings:
	$a0 = { 43594245524c4f41524431b44eb90300bac201cd217273b8023dba9e0090cd2193b43fb90900bab901cd21beb9 }


condition:
	$a0
}