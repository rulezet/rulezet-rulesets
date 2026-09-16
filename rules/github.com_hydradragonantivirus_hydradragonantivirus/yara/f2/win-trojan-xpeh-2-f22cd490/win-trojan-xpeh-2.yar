rule Win_Trojan_XPEH_2
{
strings:
	$a0 = { 082ec6877a0000b8030050b8c70750e81ffd72062e }


condition:
	$a0
}