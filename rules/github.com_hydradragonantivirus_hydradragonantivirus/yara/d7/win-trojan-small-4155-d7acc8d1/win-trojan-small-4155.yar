rule Win_Trojan_Small_4155
{
strings:
	$a0 = { cd2ae81600000053c3816c050078a623 }


condition:
	$a0
}