rule Win_Trojan_Bazil_1
{
strings:
	$a0 = { 010181c70001e80300e93902b93e05bb530203df8037 }


condition:
	$a0
}