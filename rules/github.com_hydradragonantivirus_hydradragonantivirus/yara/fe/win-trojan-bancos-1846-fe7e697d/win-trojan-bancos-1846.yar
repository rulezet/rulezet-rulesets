rule Win_Trojan_Bancos_1846
{
strings:
	$a0 = { 44406cb6d7acdae3f084a3fc0ccffbc032cca9c3f609d8c5b9e7f831abe91b7e15fa9570e7fa1c41755ddc17782c5bb48330e85135a51fb7ed56ba2239fe76d8f6526604f9b3 }


condition:
	$a0
}