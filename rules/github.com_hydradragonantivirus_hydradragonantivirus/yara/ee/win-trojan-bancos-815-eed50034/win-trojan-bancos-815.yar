rule Win_Trojan_Bancos_815
{
strings:
	$a0 = { 176ab84172678fafc85024406cc1dc8f47cd0fa1d61890b7c013cf4d3106adbabab62b67c1e22d58fa70bac5a0eed589ef61071bfbc3c359285c1030d42c8200c01e1d45906e }


condition:
	$a0
}