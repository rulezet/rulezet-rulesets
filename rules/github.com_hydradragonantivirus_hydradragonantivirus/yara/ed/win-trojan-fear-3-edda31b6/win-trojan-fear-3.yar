rule Win_Trojan_Fear_3
{
strings:
	$a0 = { 54592bcc83c10451ba5f02b103b44ecd }


condition:
	$a0
}