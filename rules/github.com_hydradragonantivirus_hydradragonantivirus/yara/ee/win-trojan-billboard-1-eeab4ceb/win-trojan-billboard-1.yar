rule Win_Trojan_Billboard_1
{
strings:
	$a0 = { 018bf7ad355db0abadb103d2c8abeb00bf25018be758cd20a9 }


condition:
	$a0
}