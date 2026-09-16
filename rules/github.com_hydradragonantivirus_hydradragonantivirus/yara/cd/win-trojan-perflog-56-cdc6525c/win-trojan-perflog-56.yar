rule Win_Trojan_Perflog_56
{
strings:
	$a0 = { 55455353686b2e646c6ce0722389b727005e1f214259a525b5ce1267d88631b8ea7bb704fb17796aad }


condition:
	$a0
}