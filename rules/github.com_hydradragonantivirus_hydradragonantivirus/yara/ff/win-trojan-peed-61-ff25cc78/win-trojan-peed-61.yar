rule Win_Trojan_Peed_61
{
strings:
	$a0 = { 68bdcaffff488d6c200083c5fe83c5fd6609ed0f84 }


condition:
	$a0
}