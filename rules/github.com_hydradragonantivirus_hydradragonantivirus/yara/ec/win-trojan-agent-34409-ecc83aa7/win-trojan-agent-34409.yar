rule Win_Trojan_Agent_34409
{
strings:
	$a0 = { 33d833d833d833d833d833d833d833d833d833d833d833d833d833d833c033c0 }


condition:
	$a0
}