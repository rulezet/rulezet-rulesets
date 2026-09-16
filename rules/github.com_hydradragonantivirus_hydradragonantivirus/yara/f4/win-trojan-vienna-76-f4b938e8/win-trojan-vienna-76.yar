rule Win_Trojan_Vienna_76
{
strings:
	$a0 = { 80f2aeb90400acae75ede2fa5e0789bca7008bfe }


condition:
	$a0
}