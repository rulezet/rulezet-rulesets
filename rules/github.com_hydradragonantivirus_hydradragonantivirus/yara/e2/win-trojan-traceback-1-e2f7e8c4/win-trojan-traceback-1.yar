rule Win_Trojan_Traceback_1
{
strings:
	$a0 = { e005b419cd218884e300e8ce048a95e2000e1f7509 }


condition:
	$a0
}