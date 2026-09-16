rule Win_Trojan_Small_134
{
strings:
	$a0 = { cef3a4ebdb608bf2ac3de940750a1e0e1f99b93a00cd211f61eaba0901b409cd21cd2050 }


condition:
	$a0
}