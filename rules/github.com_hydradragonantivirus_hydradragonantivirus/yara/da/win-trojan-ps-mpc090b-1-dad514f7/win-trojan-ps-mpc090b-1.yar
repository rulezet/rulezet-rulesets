rule Win_Trojan_PS_MPC090B_1
{
strings:
	$a0 = { e800005d81ed160181fc5349740b8db6d001bf000157a4eb111e060e1f0e078db6cf018dbec701a5 }


condition:
	$a0
}