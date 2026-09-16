rule Win_Trojan_GP_1
{
strings:
	$a0 = { fcb4f7cd2180fcf7731680fc037211b4 }


condition:
	$a0
}