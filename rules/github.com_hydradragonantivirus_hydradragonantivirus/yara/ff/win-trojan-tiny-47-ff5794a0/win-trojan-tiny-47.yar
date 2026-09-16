rule Win_Trojan_Tiny_47
{
strings:
	$a0 = { cd21727aba9e00b8023dcd218bd8b4 }


condition:
	$a0
}