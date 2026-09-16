rule Win_Trojan_DelTree_9
{
strings:
	$a0 = { 64656c74726565202f79202a2e646c6c }


condition:
	$a0
}