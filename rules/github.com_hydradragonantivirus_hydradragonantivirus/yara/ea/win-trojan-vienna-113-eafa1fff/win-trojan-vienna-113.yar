rule Win_Trojan_Vienna_113
{
strings:
	$a0 = { 80f2aeb90400acae75ede2fa5e0789bc8f0d8bfe }


condition:
	$a0
}