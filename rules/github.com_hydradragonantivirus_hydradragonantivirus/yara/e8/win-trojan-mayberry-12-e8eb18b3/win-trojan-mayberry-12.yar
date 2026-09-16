rule Win_Trojan_Mayberry_12
{
strings:
	$a0 = { cd21726e93b80057cd215152b43fb91c008d96df03 }


condition:
	$a0
}