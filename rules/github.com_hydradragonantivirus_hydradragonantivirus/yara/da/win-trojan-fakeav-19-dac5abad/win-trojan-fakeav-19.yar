rule Win_Trojan_Fakeav_19
{
strings:
	$a0 = { e82200000000bf8c005c0000000000000000d60000002c }


condition:
	$a0
}