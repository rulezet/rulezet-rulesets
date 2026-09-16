rule Win_Trojan_VCL_MUT_3
{
strings:
	$a0 = { bbeb09b805feebfc80c43bebf4bb1d010e07cd21b001cd21eb02ebfec606250182b080e621b44abb8602cd21bc }


condition:
	$a0
}