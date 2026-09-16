rule Win_Trojan_Vgen_131
{
strings:
	$a0 = { 0d00b43b8d56c0cd218be55dc35c0055b42fcd21538bec81ec8000b41a8d5680cd21b44eb910 }


condition:
	$a0
}