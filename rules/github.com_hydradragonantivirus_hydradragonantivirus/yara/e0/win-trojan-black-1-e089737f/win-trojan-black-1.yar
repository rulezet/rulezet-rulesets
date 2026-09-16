rule Win_Trojan_Black_1
{
strings:
	$a0 = { 03d6cd211e0706b42fcd218c444a895c4c07b41aba }


condition:
	$a0
}