rule Win_Trojan_Dutch_5
{
strings:
	$a0 = { b8c700b384e8a101a30500890e0700fb }


condition:
	$a0
}