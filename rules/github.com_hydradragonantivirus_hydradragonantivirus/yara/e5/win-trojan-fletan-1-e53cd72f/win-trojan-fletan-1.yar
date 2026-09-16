rule Win_Trojan_Fletan_1
{
strings:
	$a0 = { cd212d0300a32e00b440b93502ba0000cd21b8004233c999cd21b440b90400ba2d00cd2158 }


condition:
	$a0
}