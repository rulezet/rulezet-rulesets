rule Win_Trojan_Vgen_110
{
strings:
	$a0 = { ff0080120023006c6170696464616e56e800005e2e899cb3012e8c84b5015ecb1e06600e1fe800005d2ec49e9e }


condition:
	$a0
}