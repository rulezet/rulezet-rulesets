rule Win_Trojan_Zbot_1235
{
strings:
	$a0 = { 5589e583ec1c6a00b397ff15c6a0420085 }

	$a1 = { e0454447344d4f60 }


condition:
	$a0 and $a1
}