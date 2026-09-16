rule Win_Trojan_K_10
{
strings:
	$a0 = { f8c3061fc706be020000b81c35cd21891eea028c06 }


condition:
	$a0
}