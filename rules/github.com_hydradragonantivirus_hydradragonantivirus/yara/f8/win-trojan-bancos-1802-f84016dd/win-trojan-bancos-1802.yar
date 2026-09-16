rule Win_Trojan_Bancos_1802
{
strings:
	$a0 = { fb663959ed36b14d7ed15e146b56c9ea0ae43aeb419e1bef2d41132cd4b777f6d0e42525ee59fc962834e58e14d8e5dd4a8692bee4a1f2ec69538a926076d59c80ccfdf78b9c }


condition:
	$a0
}