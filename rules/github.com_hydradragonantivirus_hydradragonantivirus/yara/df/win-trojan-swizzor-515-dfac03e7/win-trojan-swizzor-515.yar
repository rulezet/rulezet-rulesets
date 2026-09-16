rule Win_Trojan_Swizzor_515
{
strings:
	$a0 = { e8000000005a81c2????0800ffe2 }


condition:
	$a0
}