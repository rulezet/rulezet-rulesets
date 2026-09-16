rule Win_Trojan_StupidRock_1
{
strings:
	$a0 = { e9894501ba9702b91800b440cd2172043bc17401f9c3 }


condition:
	$a0
}