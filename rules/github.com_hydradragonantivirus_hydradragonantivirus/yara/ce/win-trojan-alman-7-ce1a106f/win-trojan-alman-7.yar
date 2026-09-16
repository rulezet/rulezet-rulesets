rule Win_Trojan_Alman_7
{
strings:
	$a0 = { 33d8cc5bb99e04000080??19??e2faeb06e8edffffffc3 }


condition:
	$a0
}