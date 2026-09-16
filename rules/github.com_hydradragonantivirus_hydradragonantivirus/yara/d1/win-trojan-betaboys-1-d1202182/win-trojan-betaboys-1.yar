rule Win_Trojan_BetaBoys_1
{
strings:
	$a0 = { e800005d81ed0301b844008ec0bf00018bf703f53e8b8e6201f3a48ed9be84008dbebf028d9664012bfd2bd5ad3bc27417aba50e1fb800008ec0bf84008d8664 }


condition:
	$a0
}