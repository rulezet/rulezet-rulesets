rule Win_Trojan_SillyRC_3
{
strings:
	$a0 = { 53521e80ec4b7543b8023dcd21723c93b903000e1f33d2 }


condition:
	$a0
}