rule Win_Trojan_MPC_2
{
strings:
	$a0 = { 8b6efa81ed03001e06b84144cd213d535074528cd8488ed8832e03002390832e12002390 }


condition:
	$a0
}