rule Win_Trojan_Small_4405
{
strings:
	$a0 = { 56e99d000000e847000000e8e3000000 }


condition:
	$a0
}