rule Win_Trojan_Malaga_2
{
strings:
	$a0 = { 2acd2181f9c807720b80fa017506c6063a0a0190b41aba }


condition:
	$a0
}