rule Win_Trojan_SillyC_246
{
strings:
	$a0 = { e800005d83ed0487fe8bf581c6cb00a5a5b41a8bd581c2cf00cd21b44e8bd581c2c500b9fe00cd21 }


condition:
	$a0
}