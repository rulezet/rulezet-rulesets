rule Win_Trojan_Phoebe_2
{
strings:
	$a0 = { 0601b90300bf00018db6db0af3a4e90000b44eb907008d96c901cd217318e900008d96cf01b43bcd2173e6e964 }


condition:
	$a0
}