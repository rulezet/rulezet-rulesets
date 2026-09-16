rule Win_Trojan_VB_1622
{
strings:
	$a0 = { 302d436865727479003063617461 }


condition:
	$a0
}