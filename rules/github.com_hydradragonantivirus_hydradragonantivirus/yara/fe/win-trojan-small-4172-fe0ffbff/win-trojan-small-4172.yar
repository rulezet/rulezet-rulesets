rule Win_Trojan_Small_4172
{
strings:
	$a0 = { eb3052e8000000005b6631db }


condition:
	$a0
}