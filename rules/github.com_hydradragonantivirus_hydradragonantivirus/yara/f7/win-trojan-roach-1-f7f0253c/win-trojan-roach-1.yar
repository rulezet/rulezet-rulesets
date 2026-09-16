rule Win_Trojan_Roach_1
{
strings:
	$a0 = { 52e83600500e1fb440b9cf0133d2e858ffe82c0033d281c2cf0183ea0389d6b4e9882458fe }


condition:
	$a0
}