rule Win_Trojan_Bach_1
{
strings:
	$a0 = { 515256571e06fcbe8000bf10fdb98000f3a48b360a01b44eb907008bd683c217cd217303e96101f606950004757e }


condition:
	$a0
}