rule Win_Trojan_SillyRC_7
{
strings:
	$a0 = { 565fe800005e83c63c90a4a533c08ec0bf000283ee459060a761b19a9090f3a4741b511fbe840056a5a55e56bfe003 }


condition:
	$a0
}