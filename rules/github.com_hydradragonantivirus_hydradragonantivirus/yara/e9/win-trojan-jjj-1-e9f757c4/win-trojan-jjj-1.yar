rule Win_Trojan_JJJ_1
{
strings:
	$a0 = { 803e1b1f8c7403e97f01b8230050b8021050b83c0f50e85b088be50bc07403e96701b80b00 }


condition:
	$a0
}