rule Win_Trojan_Bancos_1499
{
strings:
	$a0 = { 5db2bb17920699be8d5d4d94edfda9f63322bfc31e566c6ac9f8bbf4569a9d546fd86d668dc6f716de6df8f3d14b3e50 }

	$a1 = { 7c07257115475da16bbe3a4d52a3b893d5941becbfe27a4ff7cf5209c3876f900fe404983f38c2ea4138f926fd98fecec474bc8196950ed23b70 }


condition:
	$a0 and $a1
}