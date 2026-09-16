rule Win_Trojan_Small_4377
{
strings:
	$a0 = { 558becb838250000e8b206000053 }


condition:
	$a0
}