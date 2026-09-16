rule Win_Trojan_Doolbow_2
{
strings:
	$a0 = { e1d5cb98943272ee2a4f7f6efeb2c2dc738fa965f76bffff8707f49d9db698db6f5f2d1a6295b9f9e695e632ab93fe8e }


condition:
	$a0
}