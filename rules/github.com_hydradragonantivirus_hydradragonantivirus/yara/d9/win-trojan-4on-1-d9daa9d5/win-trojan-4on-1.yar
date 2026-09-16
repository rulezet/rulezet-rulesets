rule Win_Trojan_4on_1
{
strings:
	$a0 = { ad33062205abe2f2b91c00ba2405b440e895fee8aafeb80042e88cfeb440b94205ba4205e881fe }


condition:
	$a0
}