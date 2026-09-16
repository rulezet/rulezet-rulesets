rule Win_Trojan_Codewar_1
{
strings:
	$a0 = { 3ace780a3f1e53a5a15cc1b8be89c2aad7a437fa2bedae }


condition:
	$a0
}