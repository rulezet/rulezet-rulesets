rule Win_Trojan_Diablo_2
{
strings:
	$a0 = { fd7728a38f00b80057cc5152b97f01b44099cc7210b8004233c999ccb90400ba8d00b440cc }


condition:
	$a0
}