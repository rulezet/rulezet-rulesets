rule Win_Trojan_Small_131
{
strings:
	$a0 = { 504b0304140009000800 }

	$a1 = { 2e636f6d2e66726175642e73656375726974792e7069662e706966 }


condition:
	$a0 and $a1
}