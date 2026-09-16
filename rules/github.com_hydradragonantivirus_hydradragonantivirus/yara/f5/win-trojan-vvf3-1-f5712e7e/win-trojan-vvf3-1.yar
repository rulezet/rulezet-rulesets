rule Win_Trojan_VVF3_1
{
strings:
	$a0 = { c300018bf3fcf3a41eb8000153cb8cd8488ed88b1e }


condition:
	$a0
}