rule Win_Trojan_NumberofBeast_1
{
strings:
	$a0 = { 520e070e1f1eb05050b43fcbcd2172 }


condition:
	$a0
}