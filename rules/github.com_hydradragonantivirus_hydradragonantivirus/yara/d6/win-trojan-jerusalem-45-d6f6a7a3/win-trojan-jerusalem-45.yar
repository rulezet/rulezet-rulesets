rule Win_Trojan_Jerusalem_45
{
strings:
	$a0 = { 0181c1100633d2b440cd212ea153018ec0b449cd212e8b1e4b01b43ecd212ea147018ed8 }


condition:
	$a0
}