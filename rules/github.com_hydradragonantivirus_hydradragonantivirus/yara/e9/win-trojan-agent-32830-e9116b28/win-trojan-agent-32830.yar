rule Win_Trojan_Agent_32830
{
strings:
	$a0 = { 3656ef7b798c895c3f470ed237e756e1aeaeaff09f7fa869e32bc37a11ac297bc1094a6f9cc7e6b9ce7373bad4c6680ad494458d5c80dbdcb6bf9e8d69518f3caa }


condition:
	$a0
}