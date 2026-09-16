rule Win_Trojan_Proxy_75
{
strings:
	$a0 = { dd6033fbeb0051b912b5c63656eb0081ee10084e8c33f05e59eb0255f151525681f69f04bfd95e7c005aeb0059eb01ca0f51 }


condition:
	$a0
}