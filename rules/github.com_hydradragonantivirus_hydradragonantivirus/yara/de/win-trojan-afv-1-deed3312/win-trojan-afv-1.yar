rule Win_Trojan_AFV_1
{
strings:
	$a0 = { 3b060b017225ba0403b4402e8b0e0b01cd217217b8004233c933d2cd21720cba0001b4402e8b }


condition:
	$a0
}