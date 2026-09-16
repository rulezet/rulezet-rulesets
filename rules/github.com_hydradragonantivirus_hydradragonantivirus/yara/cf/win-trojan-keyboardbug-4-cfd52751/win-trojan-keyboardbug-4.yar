rule Win_Trojan_KeyboardBug_4
{
strings:
	$a0 = { 0806b91201582e300143e2fa }


condition:
	$a0
}