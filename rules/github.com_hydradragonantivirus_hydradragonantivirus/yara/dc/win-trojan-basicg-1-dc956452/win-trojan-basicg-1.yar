rule Win_Trojan_BasicG_1
{
strings:
	$a0 = { a360008c066200c7064c007f7c8c0e4e00c70670004d }


condition:
	$a0
}