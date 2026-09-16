rule Win_Trojan_Danish_Tiny_1
{
strings:
	$a0 = { b4408d940501b91c01cd219c9d7201c3e98e00 }


condition:
	$a0
}