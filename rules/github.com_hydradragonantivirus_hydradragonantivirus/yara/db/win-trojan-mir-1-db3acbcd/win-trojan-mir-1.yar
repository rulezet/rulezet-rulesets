rule Win_Trojan_MIR_1
{
strings:
	$a0 = { bcce064d5a7410fa908be681c4d107 }


condition:
	$a0
}