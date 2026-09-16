rule Win_Trojan_Caos_1
{
strings:
	$a0 = { e80000cc5d81ed06012efe862d012e80be350100741e0e0e071f8db637018bfe2e8a9e3601b9980290ac2fd8aae2faeb }


condition:
	$a0
}