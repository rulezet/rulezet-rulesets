rule Win_Trojan_Alman_2
{
strings:
	$a0 = { eb1133d8cc5bb9cd040000803419??e2faeb06e8edfffffffc }


condition:
	$a0
}