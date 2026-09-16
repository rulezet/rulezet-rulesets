rule Win_Trojan_AsmVirus_1
{
strings:
	$a0 = { fcb44ebae301cd21ba9e008bf2bff0015757b90d00f3a45fb02eb90d00f2aea1e901aba1eb }


condition:
	$a0
}