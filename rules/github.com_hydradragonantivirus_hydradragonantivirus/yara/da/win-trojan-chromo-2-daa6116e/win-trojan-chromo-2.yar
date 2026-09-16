rule Win_Trojan_Chromo_2
{
strings:
	$a0 = { 86990200c6869a0200eb00b44eb9ff018d965602cc3d }


condition:
	$a0
}