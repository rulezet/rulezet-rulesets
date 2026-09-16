rule Win_Trojan_Gro_1
{
strings:
	$a0 = { e952e3c107c32970d09062c7e4a44763e4c8637e5d7ae5412968e5c1a4e5ff296de747e461d1acd3 }


condition:
	$a0
}