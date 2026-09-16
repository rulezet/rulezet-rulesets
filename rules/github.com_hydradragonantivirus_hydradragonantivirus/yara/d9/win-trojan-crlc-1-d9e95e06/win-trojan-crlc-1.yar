rule Win_Trojan_CRLC_1
{
strings:
	$a0 = { 0e1fc406d801a386018c068801b41aba8a01cd21b82a2ea3ba01354f56a3bc0132e4a3be01b82435cd21891eb601 }


condition:
	$a0
}