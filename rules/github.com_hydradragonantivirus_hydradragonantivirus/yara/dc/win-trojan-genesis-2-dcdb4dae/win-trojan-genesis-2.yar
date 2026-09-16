rule Win_Trojan_Genesis_2
{
strings:
	$a0 = { e800005d81ed03018db6d501bf000157a5a58d96d901b41acd21b44eb907008d96cb01cd217202eb0e33c08bd88bc88bd0be00018bf8c38d96f701b80043cd21 }


condition:
	$a0
}